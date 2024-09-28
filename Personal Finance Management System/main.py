import bcrypt
from flask import Flask, render_template, request, url_for, redirect, session, flash, jsonify
import os
from datetime import timedelta
import pandas as pd
import json
import warnings
import pymysql
import support
import re
from datetime import datetime
from flask_mail import Mail, Message
import random
import plotly.express as px
import plotly.graph_objs as go
import traceback

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
    name = request.form.get("name")
    email = request.form.get("email")
    phone = request.form.get("phone")
    sub = request.form.get("sub")
    message = request.form.get("message")
    flash("Thanks for reaching out to us. We will contact you soon.")
    return redirect('/')


@app.route('/home')
def home():
    if 'user_id' in session:
        query = f"SELECT * FROM user_login WHERE user_id = {session['user_id']}"
        userdata = execute_query("search", query)

        table_query = f"SELECT * FROM user_expenses WHERE user_id = {session['user_id']} ORDER BY pdate DESC"
        table_data = execute_query("search", table_query)
        df = pd.DataFrame(table_data, columns=['#', 'User_Id', 'Date', 'Expense', 'Amount', 'Note'])

        df = support.generate_df(df)

        # Initialize earnings, spend, invest, and savings
        earning, spend, invest, saving = 0, 0, 0, 0

        # Check for income and expense data to handle empty DataFrame gracefully
        if not df.empty:
            try:
                earning, spend, invest, saving = support.top_tiles(df)

                # Calculate total income and total expenses
                total_income = df[df['Expense'] == 'Earning']['Amount'].sum()
                total_expenses = df[df['Expense'] == 'Spend']['Amount'].sum()
                saving = total_income - total_expenses  # Update `saving`
                # Validate that expenses are not greater than income
                if total_expenses > total_income:
                    flash("Warning: Your total expenses exceed your total income!")
            except Exception as e:
                # Handle errors in calculating top_tiles
                flash(f"Error calculating financial data: {str(e)}")
                earning, spend, invest, saving = 0, 0, 0, 0

        # Proceed with generating graphs and other statistics
        try:
            bar, pie, line, stack_bar = support.generate_Graph(df)
        except:
            bar, pie, line, stack_bar = None, None, None, None

        try:
            monthly_data = support.get_monthly_data(df, res=None)
        except:
            monthly_data = []

        # Remove unused variables such as card_data and goals since they don't appear in your template
        # Simplify pie chart handling for the three charts displayed in the template
        try:
            pie1 = support.makePieChart(df, 'Earning', 'Month_name')
            pie2 = support.makePieChart(df, 'Spend', 'Day_name')
            pie3 = support.makePieChart(df, 'Investment', 'Year')
        except:
            pie1, pie2, pie3 = None, None, None

        # Check and display user alerts
        alerts = check_alerts(session['user_id'])
        if alerts:
            for alert in alerts:
                flash(alert)

        # Render template with updated variables
        return render_template('home.html',
                               user_name=userdata[0][1],
                               df_size=df.shape[0],
                               earning=earning,
                               spend=spend,
                               invest=invest,
                               saving=saving,
                               monthly_data=monthly_data,
                               table_data=table_data[0:5],
                               bar_labels=json.dumps(bar['labels']) if bar else '[]',
                               bar_income=json.dumps(bar['income']) if bar else '[]',
                               bar_spend=json.dumps(bar['spend']) if bar else '[]',
                               stacked_labels=json.dumps(stack_bar['labels']) if stack_bar else '[]',
                               stacked_income=json.dumps(stack_bar['income']) if stack_bar else '[]',
                               stacked_spend=json.dumps(stack_bar['spend']) if stack_bar else '[]',
                               stacked_invest=json.dumps(stack_bar['invest']) if stack_bar else '[]',
                               pie_labels1=json.dumps(pie1['labels']) if pie1 else '[]',
                               pie_data1=json.dumps(pie1['data']) if pie1 else '[]',
                               pie_labels2=json.dumps(pie2['labels']) if pie2 else '[]',
                               pie_data2=json.dumps(pie2['data']) if pie2 else '[]',
                               pie_labels3=json.dumps(pie3['labels']) if pie3 else '[]',
                               pie_data3=json.dumps(pie3['data']) if pie3 else '[]',
                               )

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
    # Query to get income data for the user
    income_query = f"""
        SELECT pdate, amount 
        FROM user_expenses 
        WHERE user_id = {user_id} AND expense = 'earning'
        ORDER BY pdate
    """
    income_data = execute_query("search", income_query)

    # Format income data as required
    income_data_formatted = [{'date': str(row[0]), 'amount': row[1]} for row in income_data]

    # Query to get expense data for the user
    expense_query = f"""
        SELECT pdate, expense, amount, pdescription 
        FROM user_expenses 
        WHERE user_id = {user_id} AND expense = 'spend'
        ORDER BY pdate
    """
    expense_data = execute_query("search", expense_query)

    # Format expense data as required
    expense_data_formatted = [{'date': str(row[0]), 'category': row[1], 'amount': row[2]} for row in expense_data]

    return income_data_formatted, expense_data_formatted


@app.route('/analysis')
def analysis():
    user_id = session.get('user_id')  # Fetch user id from session
    user_name = session.get('user_name')

    # Fetch income and expense data for the user
    try:
        income_data, expense_data = get_finance_data(user_id)

        # Ensure income_data and expense_data are valid before proceeding
        if not income_data:
            income_data = []
        if not expense_data:
            expense_data = []

        # Calculate summary statistics
        total_income = sum([item['amount'] for item in income_data])
        total_expenses = sum([item['amount'] for item in expense_data])
        net_savings = total_income - total_expenses
        goal_progress = (net_savings / total_income) * 100 if total_income > 0 else 0

        # Prepare data for Pie chart (Income vs Expenses)
        pie_data = {
            'labels': ['Income', 'Expenses'],
            'datasets': [{
                'data': [total_income, total_expenses],
                'backgroundColor': ['#36A2EB', '#FF6384']
            }]
        }

        # Prepare data for Category-wise expenses (Bar chart)
        df_expense = pd.DataFrame(expense_data)
        if not df_expense.empty and 'category' in df_expense.columns:
            category_expenses = df_expense.groupby('category')['amount'].sum().reset_index()
            stack_bar_data = {
                'labels': category_expenses['category'].tolist(),
                'datasets': [{
                    'label': 'Expenses by Category',
                    'data': category_expenses['amount'].tolist(),
                    'backgroundColor': '#FF9F40'
                }]
            }
        else:
            stack_bar_data = None  # Handle case where expense data is empty or 'category' column is missing

        # Prepare data for Income trends (Line chart)
        df_income = pd.DataFrame(income_data)
        if not df_income.empty and 'date' in df_income.columns:
            df_income['date'] = pd.to_datetime(df_income['date'])
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
            line_graph_data = None  # Handle case where income data is empty or 'date' column is missing

        # Pass data to the template
        return render_template('analysis.html',
                               user_name=user_name,
                               total_income=total_income,
                               total_expenses=total_expenses,
                               net_savings=net_savings,
                               goal_progress=goal_progress,
                               pie_data=pie_data,
                               stack_bar_data=stack_bar_data,
                               line_graph_data=line_graph_data)

    except Exception as e:
        print(f"Error during analysis: {e}")
        print(traceback.format_exc())  # Print the full traceback
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
