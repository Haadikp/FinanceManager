import math
import os
import random
import re
import csv
import io
import traceback
import warnings
from datetime import datetime, timedelta

import bcrypt
import pandas as pd
from flask import Flask, render_template, make_response, request, redirect, flash, session, Response
from flask_mail import Mail, Message
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text

import support

warnings.filterwarnings("ignore")

# ──────────────────────────────────────────────────────────
# App & DB Setup
# ──────────────────────────────────────────────────────────
app = Flask(__name__)
# IMPORTANT: must be a stable string — os.urandom() changes every cold start, breaking sessions on Vercel
app.secret_key = os.environ.get('SECRET_KEY', 'pfms-dev-secret-key-change-in-production')

# Database URI: use Neon / Postgres on Vercel, SQLite locally
database_url = os.environ.get('DATABASE_URL', 'sqlite:///finance.db')
# Fix Heroku/Neon-style "postgres://" → SQLAlchemy prefers "postgresql://"
if database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# ──────────────────────────────────────────────────────────
# Flask-Mail configuration (env vars, no hardcoded secrets)
# ──────────────────────────────────────────────────────────
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'pfms-dev-secret-key-change-in-production')
app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', '')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', '')
app.config['MAIL_DEBUG'] = False
mail = Mail(app)

# ──────────────────────────────────────────────────────────
# ORM Models  (column names match existing DB schema)
# ──────────────────────────────────────────────────────────
class UserLogin(db.Model):
    __tablename__ = 'user_login'
    user_id   = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username  = db.Column(db.String(100), nullable=False)
    email     = db.Column(db.String(150), unique=True, nullable=False)
    password  = db.Column(db.String(300), nullable=False)

class UserExpense(db.Model):
    __tablename__ = 'user_expenses'
    id           = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id      = db.Column(db.Integer, db.ForeignKey('user_login.user_id'), nullable=False)
    pdate        = db.Column(db.Date, nullable=False)
    expense      = db.Column(db.String(50), nullable=False)   # Earning / Spend / Investment
    amount       = db.Column(db.Float, nullable=False)
    pdescription = db.Column(db.String(255), default='')

class UserAlert(db.Model):
    __tablename__ = 'user_alerts'
    alert_id   = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id    = db.Column(db.Integer, db.ForeignKey('user_login.user_id'), nullable=False)
    alert_type = db.Column(db.String(50), nullable=False)
    threshold  = db.Column(db.Float, nullable=False)
    active     = db.Column(db.Boolean, default=True)

# ── Lazy DB init: runs once on the first request, NOT at import time.
# Module-level db.create_all() crashes Vercel serverless functions during cold start
# if the DB connection is slow or the SSL handshake isn't complete yet.
_db_initialized = False

@app.before_request
def _lazy_init_db():
    global _db_initialized
    if not _db_initialized:
        try:
            db.create_all()
            _db_initialized = True
        except Exception as e:
            print(f"[DB INIT] Warning: {e}")

# ──────────────────────────────────────────────────────────
# Helper: check user alerts
# ──────────────────────────────────────────────────────────
def check_alerts(user_id):
    alerts = UserAlert.query.filter_by(user_id=user_id).all()
    messages = []
    for alert in alerts:
        if alert.active:
            if alert.alert_type == 'expense':
                total = db.session.query(db.func.sum(UserExpense.amount))\
                    .filter_by(user_id=user_id, expense='Spend').scalar() or 0
                if total > alert.threshold:
                    messages.append(f"⚠️ Your total expenses (₹{total:,.0f}) have exceeded your alert threshold of ₹{alert.threshold:,.0f}.")
            elif alert.alert_type == 'income':
                total = db.session.query(db.func.sum(UserExpense.amount))\
                    .filter_by(user_id=user_id, expense='Earning').scalar() or 0
                if total < alert.threshold:
                    messages.append(f"⚠️ Your total income (₹{total:,.0f}) is below your alert threshold of ₹{alert.threshold:,.0f}.")
    return messages

# ──────────────────────────────────────────────────────────
# Tax helpers (unchanged logic)
# ──────────────────────────────────────────────────────────
MAX_DEDUCTIONS = {'old': 150000, 'new': 0}

def calculate_old_regime_tax(income):
    if income <= 250000:   return 0
    elif income <= 500000: return (income - 250000) * 0.05
    elif income <= 1000000:return (250000 * 0.05) + ((income - 500000) * 0.20)
    else:                  return (250000 * 0.05) + (500000 * 0.20) + ((income - 1000000) * 0.30)

def calculate_new_regime_tax(income):
    if income <= 250000:   return 0
    elif income <= 500000: return (income - 250000) * 0.05
    elif income <= 750000: return 12500 + (income - 500000) * 0.10
    elif income <= 1000000:return 37500 + (income - 750000) * 0.15
    elif income <= 1250000:return 75000 + (income - 1000000) * 0.20
    elif income <= 1500000:return 125000 + (income - 1250000) * 0.25
    else:                  return 187500 + (income - 1500000) * 0.30

def calculate_advance_tax(total_tax):
    june  = total_tax * 0.15
    sept  = total_tax * 0.45 - june
    dec   = total_tax * 0.75 - (june + sept)
    march = total_tax - (june + sept + dec)
    remaining = total_tax - (june + sept + dec + march)
    return june, sept, dec, march, remaining

# ──────────────────────────────────────────────────────────
# Auth Routes
# ──────────────────────────────────────────────────────────
@app.route('/')
def login():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=25)
    if 'user_id' in session:
        flash("You are already logged in.", "info")
        return redirect('/home')
    return render_template('login.html')


@app.route('/login_validation', methods=['POST'])
def login_validation():
    if 'user_id' in session:
        return redirect('/home')
    email  = request.form.get('email', '').strip()
    passwd = request.form.get('password', '').strip()
    user   = UserLogin.query.filter_by(email=email).first()
    if user and bcrypt.checkpw(passwd.encode('utf-8'), user.password.encode('utf-8')):
        session['user_id'] = user.user_id
        flash(f"Welcome back, {user.username}! 👋", "success")
        return redirect('/home')
    flash("Invalid email or password. Please try again.", "danger")
    return redirect('/')


@app.route('/register')
def register():
    if 'user_id' in session:
        return redirect('/home')
    return render_template('register.html')


@app.route('/registration', methods=['POST'])
def registration():
    if 'user_id' in session:
        return redirect('/home')
    name   = request.form.get('name', '').strip()
    email  = request.form.get('email', '').strip()
    passwd = request.form.get('password', '').strip()

    if not name.replace(' ', '').isalpha() or len(name) < 5:
        flash("Name must be at least 5 characters and contain only letters.", "danger")
        return redirect('/register')
    if not re.match(r'^\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', email):
        flash("Invalid email format.", "danger")
        return redirect('/register')
    if len(passwd) < 5:
        flash("Password must be at least 5 characters.", "danger")
        return redirect('/register')
    if UserLogin.query.filter_by(email=email).first():
        flash("This email is already registered.", "danger")
        return redirect('/register')

    hashed = bcrypt.hashpw(passwd.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    new_user = UserLogin(username=name, email=email, password=hashed)
    db.session.add(new_user)
    db.session.commit()
    session['user_id'] = new_user.user_id
    flash("Account created successfully! Welcome aboard 🎉", "success")
    return redirect('/home')


@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect('/')

# ──────────────────────────────────────────────────────────
# Password Reset (OTP)
# ──────────────────────────────────────────────────────────
@app.route('/reset', methods=['POST'])
def reset():
    if 'user_id' in session:
        return redirect('/home')
    email    = request.form.get('femail', '').strip()
    userdata = UserLogin.query.filter_by(email=email).first()
    if userdata:
        otp = random.randint(100000, 999999)
        session['reset_email'] = email
        session['otp']         = otp
        try:
            msg = Message("Password Reset OTP", sender="noreply@pfms.app", recipients=[email])
            msg.body = f"Your OTP for password reset is: {otp}. It expires in 10 minutes."
            mail.send(msg)
            flash("An OTP has been sent to your email.", "success")
        except Exception:
            flash("Could not send email. Please check mail configuration.", "danger")
        return redirect('/verify_otp')
    flash("No account found with this email.", "danger")
    return redirect('/')


@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        entered_otp  = request.form.get('otp', '')
        new_password = request.form.get('new_password', '')
        if 'otp' in session and 'reset_email' in session:
            if str(session['otp']) == entered_otp:
                email  = session['reset_email']
                hashed = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                user   = UserLogin.query.filter_by(email=email).first()
                if user:
                    user.password = hashed
                    db.session.commit()
                    session.pop('otp', None)
                    session.pop('reset_email', None)
                    flash("Password reset successfully! Please log in.", "success")
                    return redirect('/')
            else:
                flash("Invalid OTP. Please try again.", "danger")
                return redirect('/verify_otp')
        else:
            flash("Session expired. Please try again.", "danger")
            return redirect('/')
    return render_template('verify_otp.html')

# ──────────────────────────────────────────────────────────
# Home / Dashboard
# ──────────────────────────────────────────────────────────
@app.route('/home')
def home():
    if 'user_id' not in session:
        return redirect('/')
    user_id  = session['user_id']
    userdata = UserLogin.query.get(user_id)

    # Fetch all expenses for this user
    rows = UserExpense.query.filter_by(user_id=user_id).order_by(UserExpense.pdate.desc()).all()
    table_data = [(r.id, r.user_id, r.pdate, r.expense, r.amount, r.pdescription) for r in rows]

    df = pd.DataFrame(table_data, columns=['#', 'User_Id', 'Date', 'Expense', 'Amount', 'Note'])
    df = support.generate_df(df) if not df.empty else df

    earning = spend = invest = saving = 0
    spending_pie_data = earning_pie_data = None
    monthly_data = []

    if not df.empty:
        try:
            # Calculate totals directly — reliable and pandas-version independent
            total_income   = float(df[df['Expense'] == 'Earning']['Amount'].sum())
            total_spend    = float(df[df['Expense'] == 'Spend']['Amount'].sum())
            total_invest   = float(df[df['Expense'] == 'Investment']['Amount'].sum())
            total_expenses = total_spend + total_invest
            saving_val     = total_income - total_expenses

            # Format for KPI card display (e.g. 1500 → "1.5K")
            earning = support.num2MB(total_income)
            spend   = support.num2MB(total_spend)
            invest  = support.num2MB(total_invest)
            saving  = support.num2MB(abs(saving_val)) if saving_val >= 0 else f"-{support.num2MB(abs(saving_val))}"

            if total_expenses > total_income:
                flash("⚠️ Warning: Your total expenses exceed your total income!", "warning")
        except Exception as e:
            flash(f"Error calculating finances: {e}", "danger")

        # Pie chart data
        try:
            df_sp = df[df['Expense'] == 'Spend']
            if not df_sp.empty:
                grp = df_sp.groupby('Note')['Amount'].sum().reset_index()
                colors = ['#4F46E5','#7C3AED','#DB2777','#DC2626','#D97706','#059669','#0891B2','#0284C7']
                spending_pie_data = {
                    'labels': grp['Note'].tolist(),
                    'datasets': [{'data': grp['Amount'].tolist(),
                                  'backgroundColor': colors[:len(grp)],
                                  'borderWidth': 2}]
                }
            df_ea = df[df['Expense'] == 'Earning']
            if not df_ea.empty:
                grp2 = df_ea.groupby('Note')['Amount'].sum().reset_index()
                colors2 = ['#059669','#10B981','#34D399','#6EE7B7','#A7F3D0','#D1FAE5']
                earning_pie_data = {
                    'labels': grp2['Note'].tolist(),
                    'datasets': [{'data': grp2['Amount'].tolist(),
                                  'backgroundColor': colors2[:len(grp2)],
                                  'borderWidth': 2}]
                }
        except Exception as e:
            flash(f"Chart error: {e}", "danger")

        # Monthly data
        try:
            df['Date'] = pd.to_datetime(df['Date'])
            df['Month'] = df['Date'].dt.strftime('%b %Y')
            monthly = df.groupby(['Month', 'Expense'])['Amount'].sum().unstack(fill_value=0).reset_index()
            for col in ['Earning', 'Spend', 'Investment']:
                if col not in monthly.columns:
                    monthly[col] = 0
            monthly['Saving'] = monthly['Earning'] - monthly['Spend'] - monthly['Investment']
            monthly_data = monthly.to_dict(orient='records')
        except Exception as e:
            flash(f"Monthly data error: {e}", "danger")

    # User alerts
    alerts = check_alerts(user_id)
    for a in alerts:
        flash(a, "warning")

    return render_template('home.html',
                           user_name=userdata.username,
                           earning=earning,
                           spend=spend,
                           invest=invest,
                           saving=saving,
                           # raw numbers for charts
                           total_income=total_income if not df.empty else 0,
                           total_spend=total_spend if not df.empty else 0,
                           total_invest=total_invest if not df.empty else 0,
                           table_data=table_data[:5],
                           pie_data1=spending_pie_data,
                           pie_data2=earning_pie_data,
                           monthly_data=monthly_data,
                           df_size=len(table_data))


@app.route('/home/add_expense', methods=['POST'])
def add_expense():
    if 'user_id' not in session:
        return redirect('/')
    user_id = session['user_id']
    date_str = request.form.get('e_date', '')
    expense  = request.form.get('e_type', '')
    amount   = request.form.get('amount', 0)
    notes_dropdown = request.form.get('notes_dropdown', '')
    custom_note    = request.form.get('custom_note', '').strip()
    notes = custom_note if custom_note else notes_dropdown

    try:
        pdate = datetime.strptime(date_str, '%Y-%m-%d')
        if pdate > datetime.now():
            flash("Date cannot be in the future.", "warning")
            return redirect('/home')
        record = UserExpense(
            user_id=user_id,
            pdate=pdate.date(),
            expense=expense,
            amount=float(amount),
            pdescription=notes
        )
        db.session.add(record)
        db.session.commit()
        flash("Transaction added successfully! ✅", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error saving transaction: {e}", "danger")
    return redirect('/home')


@app.route('/delete_expense/<int:expense_id>', methods=['POST'])
def delete_expense(expense_id):
    if 'user_id' not in session:
        return redirect('/')
    record = UserExpense.query.get_or_404(expense_id)
    if record.user_id != session['user_id']:
        flash("Unauthorized action.", "danger")
        return redirect('/analysis')
    db.session.delete(record)
    db.session.commit()
    flash("Transaction deleted.", "success")
    return redirect('/analysis')


@app.route('/edit_expense', methods=['POST'])
def edit_expense():
    if 'user_id' not in session:
        return redirect('/')
    expense_id = request.form.get('expense_id')
    record = UserExpense.query.get_or_404(expense_id)
    if record.user_id != session['user_id']:
        flash("Unauthorized action.", "danger")
        return redirect('/analysis')
    try:
        record.pdate        = datetime.strptime(request.form.get('e_date'), '%Y-%m-%d').date()
        record.expense      = request.form.get('e_type')
        record.amount       = float(request.form.get('amount'))
        record.pdescription = request.form.get('custom_note', '').strip()
        db.session.commit()
        flash("Transaction updated successfully! ✅", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error updating: {e}", "danger")
    return redirect('/analysis')

# ──────────────────────────────────────────────────────────
# Analysis
# ──────────────────────────────────────────────────────────
def get_finance_data(user_id):
    rows = UserExpense.query.filter_by(user_id=user_id).order_by(UserExpense.pdate).all()
    formatted = [{'id': r.id, 'date': str(r.pdate), 'expense': r.expense,
                  'amount': float(r.amount), 'pdescription': r.pdescription or ''} for r in rows]
    income_data  = [r for r in formatted if r['expense'] == 'Earning']
    expense_data = [r for r in formatted if r['expense'] != 'Earning']
    return income_data, expense_data


@app.route('/analysis', defaults={'page': 1})
@app.route('/analysis/page/<int:page>')
def analysis(page):
    if 'user_id' not in session:
        return redirect('/')
    user_id        = session['user_id']
    userdata       = UserLogin.query.get(user_id)
    items_per_page = 10

    # Filters
    selected_month  = request.args.get('month')
    selected_year   = request.args.get('year')
    selected_type   = request.args.get('expense_type', '')
    selected_cat    = request.args.get('category', '').strip()
    start_date_str  = request.args.get('start_date', '')
    end_date_str    = request.args.get('end_date', '')
    sort_column     = request.args.get('sort', 'date')
    sort_direction  = request.args.get('direction', 'desc')

    try:
        income_data, expense_data = get_finance_data(user_id)
        # Combine all for full table
        all_data = income_data + expense_data

        df_all    = pd.DataFrame(all_data) if all_data else pd.DataFrame(
            columns=['id','date','expense','amount','pdescription'])
        df_income = pd.DataFrame(income_data) if income_data else pd.DataFrame(
            columns=['id','date','expense','amount','pdescription'])
        df_expense = pd.DataFrame(expense_data) if expense_data else pd.DataFrame(
            columns=['id','date','expense','amount','pdescription'])

        for df in [df_all, df_income, df_expense]:
            if 'date' in df.columns and not df.empty:
                df['date'] = pd.to_datetime(df['date'], errors='coerce')

        # --- Apply filters to df_all for the table ---
        df_table = df_all.copy()
        if start_date_str:
            df_table = df_table[df_table['date'] >= pd.to_datetime(start_date_str)]
        if end_date_str:
            df_table = df_table[df_table['date'] <= pd.to_datetime(end_date_str)]
        if selected_month:
            df_table  = df_table[df_table['date'].dt.month == int(selected_month)]
            df_income = df_income[df_income['date'].dt.month == int(selected_month)] if not df_income.empty else df_income
            df_expense = df_expense[df_expense['date'].dt.month == int(selected_month)] if not df_expense.empty else df_expense
        if selected_year:
            df_table  = df_table[df_table['date'].dt.year == int(selected_year)]
            df_income = df_income[df_income['date'].dt.year == int(selected_year)] if not df_income.empty else df_income
            df_expense = df_expense[df_expense['date'].dt.year == int(selected_year)] if not df_expense.empty else df_expense
        if selected_type:
            df_table = df_table[df_table['expense'] == selected_type]
        if selected_cat:
            df_table = df_table[df_table['pdescription'].str.contains(selected_cat, case=False, na=False)]

        # Totals from filtered income/expense
        total_income   = df_income['amount'].sum() if not df_income.empty else 0
        total_expenses = df_expense['amount'].sum() if not df_expense.empty else 0
        net_savings    = total_income - total_expenses
        goal_progress  = round((net_savings / total_income) * 100, 1) if total_income > 0 else 0

        # Chart data
        pie_data = {
            'labels': ['Income', 'Expenses'],
            'datasets': [{'data': [float(total_income), float(total_expenses)],
                          'backgroundColor': ['#10B981', '#EF4444'], 'borderWidth': 0}]
        }

        stack_bar_data = None
        if not df_expense.empty and 'pdescription' in df_expense.columns:
            grp = df_expense.groupby('pdescription')['amount'].sum().reset_index()
            colors = ['#4F46E5','#7C3AED','#DB2777','#DC2626','#D97706','#059669','#0891B2','#0284C7',
                      '#6366F1','#8B5CF6','#EC4899','#F43F5E','#F59E0B','#34D399','#22D3EE','#38BDF8']
            stack_bar_data = {
                'labels': grp['pdescription'].tolist(),
                'datasets': [{'label': 'Expenses by Category',
                              'data': grp['amount'].tolist(),
                              'backgroundColor': colors[:len(grp)]}]
            }

        line_graph_data = None
        if not df_income.empty:
            dfi = df_income.sort_values('date')
            line_graph_data = {
                'labels': dfi['date'].dt.strftime('%Y-%m-%d').tolist(),
                'datasets': [{'label': 'Income', 'data': dfi['amount'].tolist(),
                              'borderColor': '#10B981', 'backgroundColor': 'rgba(16,185,129,0.1)',
                              'fill': True, 'tension': 0.4}]
            }

        expense_trend_data = None
        if not df_expense.empty:
            dfe = df_expense.sort_values('date')
            expense_trend_data = {
                'labels': dfe['date'].dt.strftime('%Y-%m-%d').tolist(),
                'datasets': [{'label': 'Expenses', 'data': dfe['amount'].tolist(),
                              'borderColor': '#EF4444', 'backgroundColor': 'rgba(239,68,68,0.1)',
                              'fill': True, 'tension': 0.4}]
            }

        # Sort table
        if sort_column in ['date', 'pdescription', 'amount', 'expense'] and not df_table.empty:
            df_table = df_table.sort_values(by=sort_column, ascending=(sort_direction == 'asc'))

        # Format date for display
        if not df_table.empty:
            df_table['date'] = df_table['date'].dt.strftime('%Y-%m-%d')

        # Years for filter dropdown
        years = []
        if not df_all.empty:
            years = sorted(df_all['date'].dt.year.dropna().unique().tolist())

        # Pagination
        total_items = len(df_table)
        total_pages = max(1, math.ceil(total_items / items_per_page))
        paginated   = df_table.iloc[(page - 1) * items_per_page: page * items_per_page].to_dict(orient='records')

        return render_template('analysis.html',
                               user_name=userdata.username,
                               total_income=total_income,
                               total_expenses=total_expenses,
                               net_savings=net_savings,
                               goal_progress=goal_progress,
                               pie_data=pie_data,
                               stack_bar_data=stack_bar_data,
                               line_graph_data=line_graph_data,
                               expense_trend_data=expense_trend_data,
                               table_data=paginated,
                               current_page=page,
                               total_pages=total_pages,
                               df_size=total_items,
                               months=list(range(1, 13)),
                               years=years,
                               selected_month=selected_month,
                               selected_year=selected_year,
                               selected_type=selected_type,
                               selected_cat=selected_cat,
                               start_date=start_date_str,
                               end_date=end_date_str,
                               per_page=items_per_page,
                               sort_column=sort_column,
                               sort_direction=sort_direction,
                               page=page)
    except Exception as e:
        print(traceback.format_exc())
        flash(f"Analysis error: {e}", "danger")
        return redirect('/home')

# ──────────────────────────────────────────────────────────
# CSV Export
# ──────────────────────────────────────────────────────────
@app.route('/export_csv')
def export_csv():
    if 'user_id' not in session:
        return redirect('/')
    rows = UserExpense.query.filter_by(user_id=session['user_id']).order_by(UserExpense.pdate.desc()).all()

    def generate():
        si = io.StringIO()
        writer = csv.writer(si)
        writer.writerow(['#', 'Date', 'Type', 'Amount (₹)', 'Description'])
        for i, r in enumerate(rows, 1):
            writer.writerow([i, r.pdate, r.expense, r.amount, r.pdescription])
            yield si.getvalue()
            si.seek(0); si.truncate(0)

    filename = f"transactions_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(generate(),
                    mimetype='text/csv',
                    headers={"Content-Disposition": f"attachment; filename={filename}"})

# ──────────────────────────────────────────────────────────
# Alerts
# ──────────────────────────────────────────────────────────
@app.route('/alerts', methods=['GET', 'POST'])
def alerts():
    if 'user_id' not in session:
        return redirect('/')
    user_id = session['user_id']
    if request.method == 'POST':
        alert_type = request.form.get('alert_type')
        threshold  = request.form.get('threshold')
        try:
            new_alert = UserAlert(user_id=user_id, alert_type=alert_type, threshold=float(threshold))
            db.session.add(new_alert)
            db.session.commit()
            flash("Alert created successfully! 🔔", "success")
        except Exception as e:
            db.session.rollback()
            flash(f"Error: {e}", "danger")
        return redirect('/alerts')
    all_alerts = UserAlert.query.filter_by(user_id=user_id).all()
    return render_template('alerts.html', alerts=all_alerts)


@app.route('/alerts/delete', methods=['POST'])
def delete_alert():
    if 'user_id' not in session:
        return redirect('/')
    alert = UserAlert.query.get_or_404(request.form.get('alert_id'))
    if alert.user_id != session['user_id']:
        flash("Unauthorized.", "danger")
        return redirect('/alerts')
    db.session.delete(alert)
    db.session.commit()
    flash("Alert deleted.", "success")
    return redirect('/alerts')


@app.route('/alerts/edit', methods=['POST'])
def edit_alert():
    if 'user_id' not in session:
        return redirect('/')
    alert = UserAlert.query.get_or_404(request.form.get('alert_id'))
    if alert.user_id != session['user_id']:
        flash("Unauthorized.", "danger")
        return redirect('/alerts')
    alert.threshold = float(request.form.get('threshold'))
    db.session.commit()
    flash("Alert updated successfully.", "success")
    return redirect('/alerts')


@app.route('/alerts/toggle', methods=['POST'])
def toggle_alert():
    if 'user_id' not in session:
        return redirect('/')
    alert = UserAlert.query.get_or_404(request.form.get('alert_id'))
    if alert.user_id != session['user_id']:
        flash("Unauthorized.", "danger")
        return redirect('/alerts')
    alert.active = not alert.active
    db.session.commit()
    status = "activated" if alert.active else "deactivated"
    flash(f"Alert {status}.", "info")
    return redirect('/alerts')

# ──────────────────────────────────────────────────────────
# Tax Calculator
# ──────────────────────────────────────────────────────────
@app.route('/calculate_tax', methods=['GET', 'POST'])
def calculate_tax():
    if request.method == 'POST':
        total_income   = float(request.form.get('income', 0))
        total_expenses = float(request.form.get('expenses', 0))
        tax_regime     = request.form.get('regime', 'new')
        session['total_income']   = total_income
        session['total_expenses'] = total_expenses
        session['tax_regime']     = tax_regime

        max_deduction = MAX_DEDUCTIONS[tax_regime]
        if total_expenses > max_deduction:
            flash(f"Deduction cannot exceed ₹{max_deduction:,.0f} for the {tax_regime} regime.", "warning")
            return render_template('tax_form.html')

        taxable_income = total_income if tax_regime == 'new' else total_income - total_expenses
        tax = calculate_old_regime_tax(taxable_income) if tax_regime == 'old' else calculate_new_regime_tax(taxable_income)
        june, sept, dec, march, remaining = calculate_advance_tax(tax)

        return render_template('tax_calculation.html',
                               total_income=total_income,
                               total_expenses=total_expenses,
                               taxable_income=taxable_income,
                               total_tax=tax,
                               tax=tax,
                               regime=tax_regime.capitalize(),
                               advance_tax_june=june,
                               advance_tax_sept=sept,
                               advance_tax_dec=dec,
                               advance_tax_march=march,
                               remaining_tax_due=remaining)
    return render_template('tax_form.html')


@app.route('/download_tax_pdf')
def download_tax_pdf():
    """PDF generation – works locally only (requires wkhtmltopdf). Gracefully fails on Vercel."""
    try:
        import pdfkit
        pdfkit_config = pdfkit.configuration(wkhtmltopdf='C:/Program Files/wkhtmltopdf/bin/wkhtmltopdf.exe')
        total_income   = session.get('total_income', 0)
        total_expenses = session.get('total_expenses', 0)
        tax_regime     = session.get('tax_regime', 'new')
        taxable_income = total_income if tax_regime == 'new' else total_income - total_expenses
        tax = calculate_old_regime_tax(taxable_income) if tax_regime == 'old' else calculate_new_regime_tax(taxable_income)
        june, sept, dec, march, remaining = calculate_advance_tax(tax)
        rendered_html = render_template('pdf_tax_summary.html',
                                        total_income=total_income,
                                        total_expenses=total_expenses,
                                        taxable_income=taxable_income,
                                        total_tax=tax, tax=tax,
                                        regime=tax_regime.capitalize(),
                                        advance_tax_june=june, advance_tax_sept=sept,
                                        advance_tax_dec=dec, advance_tax_march=march,
                                        remaining_tax_due=remaining)
        options = {'no-stop-slow-scripts': '', 'disable-local-file-access': ''}
        pdf = pdfkit.from_string(rendered_html, False, configuration=pdfkit_config, options=options)
        response = make_response(pdf)
        response.headers['Content-Type']        = 'application/pdf'
        response.headers['Content-Disposition'] = 'attachment; filename=tax_summary.pdf'
        return response
    except Exception as e:
        flash(f"PDF generation failed. This feature requires wkhtmltopdf installed locally. Error: {e}", "warning")
        return redirect('/calculate_tax')

# ──────────────────────────────────────────────────────────
# Profile
# ──────────────────────────────────────────────────────────
@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect('/')
    user = UserLogin.query.get(session['user_id'])
    return render_template('profile.html', user_name=user.username, email=user.email)


@app.route('/updateprofile', methods=['POST'])
def update_profile():
    if 'user_id' not in session:
        return redirect('/')
    user = UserLogin.query.get(session['user_id'])
    name  = request.form.get('name', '').strip()
    email = request.form.get('email', '').strip()
    changed = False
    if name and name != user.username:
        user.username = name
        changed = True
    if email and email != user.email:
        if UserLogin.query.filter(UserLogin.email == email, UserLogin.user_id != user.user_id).first():
            flash("Email already in use by another account.", "danger")
            return redirect('/profile')
        user.email = email
        changed = True
    if changed:
        db.session.commit()
        flash("Profile updated successfully! ✅", "success")
    else:
        flash("No changes detected.", "info")
    return redirect('/profile')

# ──────────────────────────────────────────────────────────
# Contact
# ──────────────────────────────────────────────────────────
@app.route('/contact')
def contact():
    return render_template('contact.html')


@app.route('/feedback', methods=['POST'])
def feedback():
    name    = request.form.get('name')
    email   = request.form.get('email')
    phone   = request.form.get('phone', '')
    subject = request.form.get('sub')
    message = request.form.get('message')
    try:
        admin_email = os.environ.get('ADMIN_EMAIL', 'admin@pfms.app')
        msg = Message(f"Contact: {subject}", sender="noreply@pfms.app", recipients=[admin_email])
        msg.body = f"From: {name}\nEmail: {email}\nPhone: {phone}\n\n{message}"
        mail.send(msg)
        flash("Your message has been sent! We'll get back to you soon. 📬", "success")
    except Exception:
        flash("Message saved but email delivery failed. Please try again later.", "warning")
    return redirect('/contact')


if __name__ == '__main__':
    app.run(debug=True)
