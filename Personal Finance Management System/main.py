import math
import os
import random
import re
import traceback
import warnings
from datetime import datetime
from datetime import timedelta
import bcrypt
import numpy as np
import pandas as pd
import pdfkit
import pymysql
from flask import Flask, render_template, make_response
from flask import request, redirect, flash
from flask import session
from flask_mail import Mail, Message

import support

warnings.filterwarnings("ignore")

# Database connection setup
db = pymysql.connect(
    host="localhost",
    user="root",
    password="",
    database="personal_finance_management_system"
)

# Initialize Flask app, __name__ is passed to tell Flask the location of the app
app = Flask(__name__)
app.secret_key = os.urandom(24)  #secret key for the Flask app to secure session data.


# Helper function to execute queries
def execute_query(query_type, query, params=None):
    global cursor
    try:
        cursor = db.cursor()  # Create a cursor object
        cursor.execute(query, params or ())

        if query_type == "search":
            result = cursor.fetchall()
            cursor.close()
            return result
        elif query_type == "insert":
            db.commit()  # Commit the changes if it is an insert query
            cursor.close()
            return

    except pymysql.MySQLError as e:
        db.rollback()  # Rollback in case of error
        cursor.close()
        print(f"Database error: {e}")
        flash("An error occurred while processing your request.")
        # Handle or log the error as needed
        return None
    except Exception as e:
        cursor.close()
        print(f"Unexpected error: {e}")
        flash("An unexpected error occurred.")
        # Handle or log the error as needed
        return None


# User alert logic
def check_alerts(user_id):
    # Use parameterized queries to prevent SQL injection
    query = "SELECT alert_type, threshold, alert_id, active FROM user_alerts WHERE user_id = %s"
    alerts = execute_query("search", query, (user_id,))

    if not alerts:
        return None

    messages = []
    for alert_type, threshold, alert_id, active in alerts:
        if active:  # Check if the alert is active
            if alert_type == "expense":
                # Query total expenses
                query = "SELECT SUM(amount) FROM user_expenses WHERE user_id = %s"
                total_expense = execute_query("search", query, (user_id,))[0][0] or 0
                if total_expense > threshold:
                    messages.append(f"Alert: Your total expenses have exceeded ₹{threshold}.")
            elif alert_type == "income":
                # Query total income
                query = "SELECT SUM(income) FROM income WHERE user_id = %s"
                total_income = execute_query("search", query, (user_id,))[0][0] or 0
                if total_income < threshold:
                    messages.append(f"Alert: Your total income is below ₹{threshold}.")

    return messages


@app.route('/')
def login():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=25)
    if 'user_id' in session:
        flash("Already a user is logged-in!")
        return redirect('/home')
    else:
        return render_template("login.html")


@app.route('/login_validation', methods=['POST', 'GET'])
def login_validation():
    if 'user_id' not in session:
        email = request.form.get('email').strip()
        passwd = request.form.get('password').strip()
        query = "SELECT * FROM user_login WHERE email = %s"
        users = execute_query("search", query, (email,))

        if users:
            stored_password = users[0][3]  # Assuming the password is in the 4th column (hashed password)
            print(passwd.encode('utf-8'))
            print(stored_password.encode('utf-8'))
            if bcrypt.checkpw(passwd.encode('utf-8'), stored_password.encode('utf-8')):
                session['user_id'] = users[0][0]
                return redirect('/home')
            else:
                flash("Incorrect password. Please try again.")
                return redirect('/')
        else:
            flash("No account found with this email address.")
            return redirect('/')
    else:
        flash("Already a user is logged-in!")
        return redirect('/home')


# Flask-Mail configuration

app.config['SECRET_KEY'] = 'qwertyuiop'
app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'kpgadgetsarena@gmail.com'
app.config['MAIL_PASSWORD'] = 'voxo isgt wxoi sqeb'
app.config['MAIL_DEBUG'] = True
mail = Mail(app)


# Password reset route using OTP
@app.route('/reset', methods=['POST'])
def reset():
    if 'user_id' not in session:
        email = request.form.get('femail')
        userdata = execute_query('search', f"SELECT * FROM user_login WHERE email = '{email}'")
        if userdata:
            # Generate a 6-digit OTP
            otp = random.randint(100000, 999999)

            # Store OTP and email in session for later validation
            session['reset_email'] = email
            session['otp'] = otp

            # Send OTP via email
            msg = Message("Password Reset OTP",
                          sender="noreply@app.com",
                          recipients=[email])
            msg.body = f"Your OTP for password reset is: {otp}. This OTP will expire in 10 minutes."
            mail.send(msg)

            flash("An OTP has been sent to your email.")
            return redirect('/verify_otp')  # Redirect to OTP verification page
        else:
            flash("Invalid email address!")
            return redirect('/')
    else:
        return redirect('/home')


# Route for verifying OTP and resetting password
@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        entered_otp = request.form.get('otp')
        new_password = request.form.get('new_password')

        if 'otp' in session and 'reset_email' in session:
            if int(entered_otp) == session['otp']:
                email = session['reset_email']

                # Hash the new password before updating
                hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

                try:
                    query = "UPDATE user_login SET password = %s WHERE email = %s"
                    execute_query('insert', query, (hashed_password, email))

                    session.pop('otp', None)
                    session.pop('reset_email', None)

                    flash("Your password has been reset successfully!")
                    return redirect('/')
                except:
                    flash("Something went wrong while resetting the password!")
                    return redirect('/verify_otp')
            else:
                flash('Invalid OTP. Please try again.')
                return redirect('/verify_otp')
        else:
            flash('Session expired or invalid. Please try again.')
            return redirect('/reset')

    return render_template('verify_otp.html')


@app.route('/register')
def register():
    if 'user_id' in session:
        flash("Already a user is logged-in!")
        return redirect('/home')
    else:
        return render_template("register.html")


@app.route('/registration', methods=['POST'])
def registration():
    if 'user_id' not in session:
        name = request.form.get('name').strip()
        email = request.form.get('email').strip()
        passwd = request.form.get('password').strip()

        if not name.replace(" ", "").isalpha() or len(name) < 5:
            flash("Name must be at least 5 characters long and contain only alphabetic characters.")
            return redirect('/register')

        email_regex = r'^\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        if not re.match(email_regex, email):
            flash("Invalid email format. Please enter a valid email address.")
            return redirect('/register')

        if len(passwd) < 5:
            flash("Password must be at least 5 characters long.")
            return redirect('/register')

        existing_user = execute_query('search', "SELECT * FROM user_login WHERE email = %s", (email,))
        if existing_user:
            flash("Email ID already exists, use another email!")
            return redirect('/register')

        try:
            hashed_password = bcrypt.hashpw(passwd.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            query = "INSERT INTO user_login(username, email, password) VALUES(%s, %s, %s)"
            execute_query('insert', query, (name, email, hashed_password))

            user = execute_query('search', "SELECT * FROM user_login WHERE email = %s", (email,))
            session['user_id'] = user[0][0]

            flash("Successfully Registered!")
            return redirect('/home')
        except Exception as e:
            flash(f"An error occurred during registration: {e}")
            return redirect('/register')
    else:
        flash("Already a user is logged-in!")
        return redirect('/home')


@app.route('/contact')
def contact():
    return render_template("contact.html")


@app.route('/feedback', methods=['POST'])
def feedback():
    # Get form data
    name = request.form.get('name')
    email = request.form.get('email')
    phone = request.form.get('phone')
    subject = request.form.get('sub')
    message_content = request.form.get('message')

    # Define the admin's email
    admin_email = 'kpgadgetsarena@example.com'  # Replace with actual admin email

    # Send feedback via email
    msg = Message(f"New Contact Us Message: {subject}",
                  sender="noreply@app.com",
                  recipients=[admin_email])  # Send to admin
    msg.body = f"""
    New message from: {name}
    Email: {email}
    Phone: {phone}

    Message:
    {message_content}
    """
    mail.send(msg)

    flash("Your message has been sent successfully!")
    return redirect('/contact')  # Redirect back to the contact page


@app.route('/home')
def home():
    if 'user_id' in session:
        # Fetch user data
        query = f"SELECT * FROM user_login WHERE user_id = {session['user_id']}"
        userdata = execute_query("search", query)

        # Fetch user expenses and create dataframe
        table_query = f"SELECT * FROM user_expenses WHERE user_id = {session['user_id']} ORDER BY pdate DESC"
        table_data = execute_query("search", table_query)
        df = pd.DataFrame(table_data, columns=['#', 'User_Id', 'Date', 'Expense', 'Amount', 'Note'])

        df = support.generate_df(df)

        # Initialize earnings, spend, invest, and savings
        earning, spend, invest, saving = 0, 0, 0, 0

        if not df.empty:
            try:
                # Calculate earnings, spend, invest, and savings using helper function
                earning, spend, invest, saving = support.top_tiles(df)

                # Calculate total income and total expenses
                total_income = df[df['Expense'] == 'Earning']['Amount'].sum()
                total_spend = df[df['Expense'] == 'Spend']['Amount'].sum()
                total_invest = df[df['Expense'] == 'Investment']['Amount'].sum()
                total_expenses = total_spend + total_invest
                saving = total_income - total_expenses

                # Flash a warning if expenses exceed income
                if total_expenses > total_income:
                    flash("Warning: Your total expenses exceed your total income!")
            except Exception as e:
                flash(f"Error calculating financial data: {str(e)}")
                earning, spend, invest, saving = 0, 0, 0, 0

        # Prepare data for category-wise pie charts (Spending and Earning)
        try:
            df_spending = df[df['Expense'] == 'Spend']
            if not df_spending.empty and 'Note' in df_spending.columns:
                spending_category_data = df_spending.groupby('Note')['Amount'].sum().reset_index()
                spending_pie_data = {
                    'labels': spending_category_data['Note'].tolist(),
                    'datasets': [{
                        'data': spending_category_data['Amount'].tolist(),
                        'backgroundColor': ['#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', '#9966FF']
                    }]
                }
            else:
                spending_pie_data = None

            df_earning = df[df['Expense'] == 'Earning']
            if not df_earning.empty and 'Note' in df_earning.columns:
                earning_category_data = df_earning.groupby('Note')['Amount'].sum().reset_index()
                earning_pie_data = {
                    'labels': earning_category_data['Note'].tolist(),
                    'datasets': [{
                        'data': earning_category_data['Amount'].tolist(),
                        'backgroundColor': ['#36A2EB', '#FFCE56', '#FF6384', '#4BC0C0', '#9966FF']
                    }]
                }
            else:
                earning_pie_data = None
        except Exception as e:
            flash(f"Error processing data for pie charts: {str(e)}")
            spending_pie_data, earning_pie_data = None, None

        # Monthly data aggregation logic
        try:
            df['Date'] = pd.to_datetime(df['Date'])
            df['Month'] = df['Date'].dt.strftime('%B %Y')

            monthly_data = df.groupby(['Month', 'Expense']).agg({'Amount': 'sum'}).unstack(fill_value=0).reset_index()
            monthly_data.columns = ['Month', 'Earning' , 'Investment', 'Spend']
            monthly_data['Saving'] = (monthly_data['Earning'] - monthly_data['Spend']) + monthly_data['Investment']
            monthly_data = monthly_data.to_dict(orient='records')
            print(monthly_data)
        except Exception as e:
            flash(f"Error calculating monthly data: {str(e)}")
            monthly_data = []

        # Check and display user alerts
        alerts = check_alerts(session['user_id'])
        if alerts:
            for alert in alerts:
                flash(alert)

        # Render home.html with the required data
        return render_template('home.html',
                               user_name=userdata[0][1],
                               earning=earning,
                               spend=spend,
                               invest=invest,
                               saving=saving,
                               table_data=table_data[0:5],  # Display first 5 records
                               pie_data1=spending_pie_data,
                               pie_data2=earning_pie_data,
                               monthly_data=monthly_data)  # Pass monthly data to the template
    else:
        return redirect('/')


@app.route('/home/add_expense', methods=['POST'])
def add_expense():
    if 'user_id' in session:
        user_id = session['user_id']
        if request.method == 'POST':
            date = request.form.get('e_date')
            expense = request.form.get('e_type')
            amount = request.form.get('amount')

            # Get selected note from the dropdown
            selected_note = request.form.get('notes_dropdown')

            # Get custom note entered by the user
            custom_note = request.form.get('custom_note')

            # Determine which note to use (custom note takes precedence if provided)
            notes = custom_note if custom_note.strip() != "" else selected_note

            if datetime.strptime(date, '%Y-%m-%d') > datetime.now():
                flash("Date cannot be in the future.")
                return redirect("/home")

            try:
                query = f"INSERT INTO user_expenses (user_id, pdate, expense, amount, pdescription) VALUES ({user_id}, '{date}', '{expense}', {amount}, '{notes}')"
                execute_query('insert', query)
                flash("Saved!")
            except Exception as e:
                flash(f"Something went wrong: {str(e)}")
                return redirect("/home")

            return redirect('/home')
    else:
        return redirect('/')


def get_finance_data(user_id):
    # Query to get all data for the user
    query = f"""
        SELECT id, pdate, expense, amount, COALESCE(pdescription, '') 
        FROM user_expenses 
        WHERE user_id = {user_id}
        ORDER BY pdate
    """
    formatted_data = execute_query("search", query)

    # Format data as required
    formatted_data = [{
        'date': str(row[1]),  # pdate
        'expense': row[2],  # expense (either 'earning' or 'spend')
        'amount': row[3],  # amount
        'pdescription': row[4]  # pdescription
    } for row in formatted_data]

    # Split into income and expense data
    income_data = [row for row in formatted_data if row['expense'] == 'Earning']
    expense_data = [row for row in formatted_data if row['expense'] == 'Spend']

    return income_data, expense_data


@app.route('/analysis', defaults={'page': 1})
@app.route('/analysis/page/<int:page>')
def analysis(page):
    user_id = session.get('user_id')
    user_name = session.get('user_name')
    items_per_page = 10  # Number of items to display per page

    # Get filter and sort parameters from request
    selected_month = request.args.get('month')
    selected_year = request.args.get('year')
    sort_column = request.args.get('sort', 'date')
    sort_direction = request.args.get('direction', 'asc')  # Default sorting is ascending

    try:
        # Fetch income and expense data using the provided function
        income_data, expense_data = get_finance_data(user_id)

        # Convert the expense and income data to pandas DataFrames for easier manipulation
        df_income = pd.DataFrame(income_data)
        df_expense = pd.DataFrame(expense_data)
        df_expense1 = df_expense.copy()

        # Ensure that the 'date' columns are in datetime format
        if 'date' in df_income.columns:
            df_income['date'] = pd.to_datetime(df_income['date'], errors='coerce')  # Convert, coerce invalids to NaT
        if 'date' in df_expense.columns:
            df_expense['date'] = pd.to_datetime(df_expense['date'], errors='coerce')
            df_expense1['date'] = pd.to_datetime(df_expense1['date'], errors='coerce')  # Convert 'df_expense1' dates as well

        # Filter by selected month and year
        if selected_month or selected_year:
            if selected_month and selected_year:
                df_income = df_income[
                    (df_income['date'].dt.month == int(selected_month)) &
                    (df_income['date'].dt.year == int(selected_year))
                ]
                df_expense = df_expense[
                    (df_expense['date'].dt.month == int(selected_month)) &
                    (df_expense['date'].dt.year == int(selected_year))
                ]
            elif selected_month:
                df_income = df_income[df_income['date'].dt.month == int(selected_month)]
                df_expense = df_expense[df_expense['date'].dt.month == int(selected_month)]
            elif selected_year:
                df_income = df_income[df_income['date'].dt.year == int(selected_year)]
                df_expense = df_expense[df_expense['date'].dt.year == int(selected_year)]


        # Convert pandas int64 to native Python float
        df_expense['amount'] = df_expense['amount'].astype(float)
        df_income['amount'] = df_income['amount'].astype(float)

        # Calculate total income and expenses
        total_income = df_income['amount'].sum() if not df_income.empty else 0
        total_expenses = df_expense['amount'].sum() if not df_expense.empty else 0
        net_savings = total_income - total_expenses
        goal_progress = (net_savings / total_income) * 100 if total_income > 0 else 0

        # Prepare pie chart data for Income vs Expenses
        pie_data = {
            'labels': ['Income', 'Expenses'],
            'datasets': [{
                'data': [total_income, total_expenses],
                'backgroundColor': ['#36A2EB', '#FF6384']
            }]
        }

        # Prepare data for stack bar chart (expenses by category)
        if not df_expense.empty and 'pdescription' in df_expense.columns:
            pdescription_expenses = df_expense.groupby('pdescription')['amount'].sum().reset_index()
            stack_bar_data = {
                'labels': pdescription_expenses['pdescription'].tolist(),
                'datasets': [{
                    'label': 'Expenses by Category',
                    'data': pdescription_expenses['amount'].tolist(),
                    'backgroundColor': '#FF9F40'
                }]
            }
        else:
            stack_bar_data = None

        # Prepare income trend line chart data
        if not df_income.empty and 'date' in df_income.columns:
            df_income = df_income.sort_values('date')
            line_graph_data = {
                'labels': df_income['date'].dt.strftime('%Y-%m-%d').tolist(),
                'datasets': [{
                    'label': 'Income Over Time',
                    'data': df_income['amount'].tolist(),
                    'borderColor': '#4BC0C0',
                    'fill': False
                }]
            }
        else:
            line_graph_data = None

        # Prepare expense trend line chart data
        if not df_expense.empty and 'date' in df_expense.columns:
            df_expense = df_expense.sort_values('date')
            expense_trend_data = {
                'labels': df_expense['date'].dt.strftime('%Y-%m-%d').tolist(),
                'datasets': [{
                    'label': 'Expenses Over Time',
                    'data': df_expense['amount'].tolist(),
                    'borderColor': '#FF6384',
                    'fill': False
                }]
            }
        else:
            expense_trend_data = None

            # Apply sorting
        if sort_column in ['date', 'pdescription', 'amount']:
            df_expense = df_expense.sort_values(by=sort_column, ascending=(sort_direction == 'asc'))

        # Pagination for transactions table
        total_items = len(df_expense)
        total_pages = math.ceil(total_items / items_per_page)
        paginated_expenses = df_expense.iloc[(page - 1) * items_per_page:page * items_per_page].to_dict(orient='records')

        # Prepare data for month and year filters
        months = list(range(1, 13))  # January to December
        years = sorted(df_expense1['date'].dt.year.dropna().unique()) if not df_expense1.empty else []

        return render_template('analysis.html',
                               user_name=user_name,
                               total_income=total_income,
                               total_expenses=total_expenses,
                               net_savings=net_savings,
                               goal_progress=goal_progress,
                               pie_data=pie_data,
                               stack_bar_data=stack_bar_data,
                               line_graph_data=line_graph_data,
                               expense_trend_data=expense_trend_data,
                               table_data=paginated_expenses,
                               current_page=page,
                               total_pages=total_pages,
                               df_size=total_items,
                               months=months,
                               years=years,
                               selected_month=selected_month,
                               selected_year=selected_year,
                               per_page=items_per_page,
                               sort_column=sort_column,
                               sort_direction=sort_direction,
                               page=page)

    except Exception as e:
        print(f"Error during analysis: {e}")
        print(traceback.format_exc())
        return "An error occurred during analysis", 500



@app.route('/alerts', methods=['GET', 'POST'])
def alerts():
    if 'user_id' not in session:
        return redirect('/')

    user_id = session['user_id']

    if request.method == 'POST':
        alert_type = request.form.get('alert_type')
        threshold = request.form.get('threshold')

        query = f"INSERT INTO user_alerts (user_id, alert_type, threshold) VALUES ({user_id}, '{alert_type}', {threshold})"
        try:
            execute_query('insert', query)
            flash("Alert has been set successfully!")
        except Exception as e:
            flash(f"An error occurred: {e}")
        return redirect('/alerts')

    # Fetch existing alerts
    query = f"SELECT alert_type, threshold, alert_id FROM user_alerts WHERE user_id = {user_id}"
    alerts = execute_query("search", query)

    # Ensure alerts is not None
    if alerts is None:
        alerts = []

    return render_template("alerts.html", alerts=alerts)


@app.route('/alerts/delete', methods=['POST'])
def delete_alert():
    if 'user_id' not in session:
        return redirect('/')

    alert_id = request.form.get('alert_id')
    query = f"DELETE FROM user_alerts WHERE alert_id = {alert_id}"
    try:
        execute_query('insert', query)
        flash("Alert has been deleted.")
    except Exception as e:
        flash(f"An error occurred: {e}")

    return redirect('/alerts')


@app.route('/alerts/edit', methods=['POST'])
def edit_alert():
    if 'user_id' not in session:
        return redirect('/')

    alert_id = request.form.get('alert_id')
    threshold = request.form.get('threshold')

    query = f"UPDATE user_alerts SET threshold = {threshold} WHERE alert_id = {alert_id}"
    try:
        execute_query('insert', query)
        flash("Alert has been updated.")
    except Exception as e:
        flash(f"An error occurred: {e}")

    return redirect('/alerts')


@app.route('/alerts/toggle', methods=['POST'])
def toggle_alert():
    if 'user_id' not in session:
        return redirect('/')

    alert_id = request.form.get('alert_id')

    # Check current status
    query = f"SELECT active FROM user_alerts WHERE alert_id = {alert_id}"
    result = execute_query('search', query)
    current_status = result[0][0]

    # Toggle the status
    new_status = not current_status
    query = f"UPDATE user_alerts SET active = {new_status} WHERE alert_id = {alert_id}"

    try:
        execute_query('insert', query)
        status = "activated" if new_status else "deactivated"
        flash(f"Alert has been {status}.")
    except Exception as e:
        flash(f"An error occurred: {e}")

    return redirect('/alerts')


@app.route('/calculate_tax', methods=['GET', 'POST'])
def calculate_tax():
    # Define maximum deductions for each regime
    MAX_DEDUCTIONS = {
        'old': 150000,  # Example limit for old regime
        'new': 0  # No deductions allowed for new regime
    }

    if request.method == 'POST':
        # Get the user inputs from the form
        total_income = float(request.form.get('income', 0))
        total_expenses = float(request.form.get('expenses', 0))
        tax_regime = request.form.get('regime', 'new')  # Get the selected regime (default is new)
        session['total_income'] = total_income
        session['total_expenses'] = total_expenses
        session['tax_regime'] = tax_regime

        # Check for maximum deduction validation
        max_deduction = MAX_DEDUCTIONS[tax_regime]
        if total_expenses > max_deduction:
            flash(f'Deduction amount cannot exceed ₹{max_deduction}. Please adjust your deduction.', 'warning')
            return render_template('tax_form.html')

        # Calculate tax based on the selected regime
        if tax_regime == 'new':
            taxable_income = total_income
        else:
            taxable_income = total_income - total_expenses

        tax = calculate_old_regime_tax(taxable_income)

        # Calculate advance tax payments
        advance_tax_june, advance_tax_sept, advance_tax_dec, advance_tax_march, remaining_tax_due = calculate_advance_tax(
            tax)

        return render_template('tax_calculation.html',
                               total_income=total_income,
                               total_expenses=total_expenses,
                               taxable_income=taxable_income,
                               total_tax=tax,
                               tax=tax,
                               regime=tax_regime.capitalize(),
                               advance_tax_june=advance_tax_june,
                               advance_tax_sept=advance_tax_sept,
                               advance_tax_dec=advance_tax_dec,
                               advance_tax_march=advance_tax_march,
                               remaining_tax_due=remaining_tax_due)
    else:
        return render_template('tax_form.html')


# # Path to wkhtmltopdf executable (only needed if it's not in your system PATH)
pdfkit_config = pdfkit.configuration(wkhtmltopdf='C:/Program Files/wkhtmltopdf/bin/wkhtmltopdf.exe')


@app.route('/download_tax_pdf')
def download_tax_pdf():
    total_income = session['total_income']
    total_expenses = session['total_expenses']
    tax_regime = session['tax_regime']
    # Render only the specific div content for the PDF

    if tax_regime == 'new':
        taxable_income = total_income
    else:
        taxable_income = total_income - total_expenses

    tax = calculate_old_regime_tax(taxable_income)

    # Calculate advance tax payments
    advance_tax_june, advance_tax_sept, advance_tax_dec, advance_tax_march, remaining_tax_due = calculate_advance_tax(
        tax)

    rendered_html = render_template('pdf_tax_summary.html',  # Use a separate template for PDF rendering
                                    total_income=total_income,
                                    total_expenses=total_expenses,
                                    taxable_income=taxable_income,
                                    total_tax=tax,
                                    tax=tax,
                                    regime=tax_regime.capitalize(),
                                    advance_tax_june=advance_tax_june,
                                    advance_tax_sept=advance_tax_sept,
                                    advance_tax_dec=advance_tax_dec,
                                    advance_tax_march=advance_tax_march,
                                    remaining_tax_due=remaining_tax_due)

    options = {
        'no-stop-slow-scripts': '',
        'disable-local-file-access': ''  # Adjust to match your Flask server's base URL
    }

    pdf = pdfkit.from_string(rendered_html, False, configuration=pdfkit_config, options=options)

    # Create a response object to send the PDF file to the user
    response = make_response(pdf)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'attachment; filename=tax_summary.pdf'

    return response


# Function to calculate tax under the new regime
def calculate_new_regime_tax(income):
    tax = 0
    if income <= 250000:
        tax = 0
    elif income <= 500000:
        tax = (income - 250000) * 0.05
    elif income <= 750000:
        tax = (250000 * 0.05) + ((income - 500000) * 0.10)
    elif income <= 1000000:
        tax = (250000 * 0.05) + (250000 * 0.10) + ((income - 750000) * 0.15)
    elif income <= 1250000:
        tax = (250000 * 0.05) + (250000 * 0.10) + (250000 * 0.15) + ((income - 1000000) * 0.20)
    elif income <= 1500000:
        tax = (250000 * 0.05) + (250000 * 0.10) + (250000 * 0.15) + (250000 * 0.20) + ((income - 1250000) * 0.25)
    else:
        tax = (250000 * 0.05) + (250000 * 0.10) + (250000 * 0.15) + (250000 * 0.20) + (250000 * 0.25) + (
                (income - 1500000) * 0.30)
    return tax


# Function to calculate tax under the old regime
def calculate_old_regime_tax(income):
    tax = 0
    if income <= 250000:
        tax = 0
    elif income <= 500000:
        tax = (income - 250000) * 0.05
    elif income <= 1000000:
        tax = (250000 * 0.05) + ((income - 500000) * 0.20)
    else:
        tax = (250000 * 0.05) + (500000 * 0.20) + ((income - 1000000) * 0.30)
    return tax


# Function to calculate advance tax payments
def calculate_advance_tax(total_tax):
    # 15% of the total tax due by June 15
    advance_tax_june = total_tax * 0.15

    # Additional 30% due by September 15 (making it 45% total including June)
    advance_tax_sept = (total_tax * 0.45) - advance_tax_june

    # Additional 30% due by December 15 (making it 75% total including previous payments)
    advance_tax_dec = (total_tax * 0.75) - (advance_tax_june + advance_tax_sept)

    # Remaining 25% due by March 15 (making it 100% total)
    advance_tax_march = total_tax - (advance_tax_june + advance_tax_sept + advance_tax_dec)

    # Remaining tax due after March (should ideally be zero)
    remaining_tax_due = total_tax - (advance_tax_june + advance_tax_sept + advance_tax_dec + advance_tax_march)

    return advance_tax_june, advance_tax_sept, advance_tax_dec, advance_tax_march, remaining_tax_due


@app.route('/profile')
def profile():
    if 'user_id' in session:  # if logged-in
        query = f"SELECT * FROM user_login WHERE user_id = {session['user_id']}"
        userdata = execute_query('search', query)
        return render_template('profile.html', user_name=userdata[0][1], email=userdata[0][2])
    else:  # if not logged-in
        return redirect('/')


@app.route("/updateprofile", methods=['POST'])
def update_profile():
    if 'user_id' in session:
        name = request.form.get('name')
        email = request.form.get('email')

        # Fetch current user data
        query = f"SELECT * FROM user_login WHERE user_id = {session['user_id']}"
        userdata = execute_query('search', query)

        # Check if the email is already taken by another user
        query = f"SELECT * FROM user_login WHERE email = '{email}' AND user_id != {session['user_id']}"
        email_list = execute_query('search', query)

        # Updating User Profile
        # If both the name and email are different from the current values and the email is not taken by another user
        if name != userdata[0][1] and email != userdata[0][2] and len(email_list) == 0:
            query = f"UPDATE user_login SET username = '{name}', email = '{email}' WHERE user_id = {session['user_id']}"
            execute_query('insert', query)
            flash("Name and Email updated!")

        # email is already taken by another user
        elif name != userdata[0][1] and email != userdata[0][2] and len(email_list) > 0:
            flash("Email already exists, try another!")

        # only email is different and not already taken
        elif name == userdata[0][1] and email != userdata[0][2] and len(email_list) == 0:
            query = f"UPDATE user_login SET email = '{email}' WHERE user_id = {session['user_id']}"
            execute_query('insert', query)
            flash("Email updated!")

        elif name == userdata[0][1] and email != userdata[0][2] and len(email_list) > 0:
            flash("Email already exists, try another!")

        # If only the name is different
        elif name != userdata[0][1] and email == userdata[0][2]:
            query = f"UPDATE user_login SET username = '{name}' WHERE user_id = {session['user_id']}"
            execute_query('insert', query)
            flash("Name updated!")
        else:
            flash("No changes made!")

        return redirect('/profile')
    else:
        return redirect('/')


@app.route('/logout')
def logout():
    session.clear()  # Clear all session data
    flash('You have been logged out.', 'info')  # Optional: Display a logout message
    return redirect('/')  # Redirect to the login page


if __name__ == "__main__":
    app.run(debug=True)
