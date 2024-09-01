from flask import Flask, render_template, request, redirect, session, flash, jsonify
import os
from datetime import timedelta
import pandas as pd
import json
import warnings
import pymysql
import support

warnings.filterwarnings("ignore")

# Database connection setup
db = pymysql.connect(
    host="localhost",
    user="root",
    password="",
    database="personal_finance_management_system"
)

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.urandom(24)


# Helper function to execute queries
def execute_query(query_type, query, params=None):
    try:
        cursor = db.cursor()
        cursor.execute(query, params or ())
        if query_type == "search":
            result = cursor.fetchall()
            cursor.close()
            return result
        elif query_type == "insert":
            db.commit()
            cursor.close()
    except Exception as e:
        print(f"An error occurred: {e}")
        db.rollback()


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
    app.permanent_session_lifetime = timedelta(minutes=15)
    if 'user_id' in session:
        flash("Already a user is logged-in!")
        return redirect('/home')
    else:
        return render_template("login.html")


@app.route('/login_validation', methods=['POST'])
def login_validation():
    if 'user_id' not in session:
        email = request.form.get('email')
        passwd = request.form.get('password')
        query = f"SELECT * FROM user_login WHERE email = '{email}' AND password = '{passwd}'"
        users = execute_query("search", query)
        if users:
            session['user_id'] = users[0][0]
            return redirect('/home')
        else:
            flash("Invalid email and password!")
            return redirect('/')
    else:
        flash("Already a user is logged-in!")
        return redirect('/home')


@app.route('/reset', methods=['POST'])
def reset():
    if 'user_id' not in session:
        email = request.form.get('femail')
        pswd = request.form.get('pswd')
        userdata = execute_query('search', f"SELECT * FROM user_login WHERE email = '{email}'")
        if userdata:
            try:
                query = f"UPDATE user_login SET password = '{pswd}' WHERE email = '{email}'"
                execute_query('insert', query)
                flash("Password has been changed!")
                return redirect('/')
            except:
                flash("Something went wrong!")
                return redirect('/')
        else:
            flash("Invalid email address!")
            return redirect('/')
    else:
        return redirect('/home')


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
        name = request.form.get('name')
        email = request.form.get('email')
        passwd = request.form.get('password')
        if len(name) > 5 and len(email) > 10 and len(passwd) > 5:
            try:
                query = f"INSERT INTO user_login(username, email, password) VALUES('{name}','{email}','{passwd}')"
                execute_query('insert', query)

                user = execute_query('search', f"SELECT * FROM user_login WHERE email = '{email}'")
                session['user_id'] = user[0][0]
                flash("Successfully Registered!")
                return redirect('/home')
            except:
                flash("Email ID already exists, use another email!")
                return redirect('/register')
        else:
            flash("Not enough data to register, try again!")
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
        try:
            earning, spend, invest, saving = support.top_tiles(df)
        except:
            earning, spend, invest, saving = 0, 0, 0, 0

        try:
            bar, pie, line, stack_bar = support.generate_Graph(df)
        except:
            bar, pie, line, stack_bar = None, None, None, None
        try:
            monthly_data = support.get_monthly_data(df, res=None)
        except:
            monthly_data = []
        try:
            card_data = support.sort_summary(df)
        except:
            card_data = []

        try:
            goals = support.expense_goal(df)
        except:
            goals = []

        try:
            size = 240
            pie1 = support.makePieChart(df, 'Earning', 'Month_name', size=size)
            pie2 = support.makePieChart(df, 'Spend', 'Day_name', size=size)
            pie3 = support.makePieChart(df, 'Investment', 'Year', size=size)
            pie4 = support.makePieChart(df, 'Saving', 'Note', size=size)
            pie5 = support.makePieChart(df, 'Saving', 'Day_name', size=size)
            pie6 = support.makePieChart(df, 'Investment', 'Note', size=size)
        except:
            pie1, pie2, pie3, pie4, pie5, pie6 = None, None, None, None, None, None

        # Check and display user alerts
        alerts = check_alerts(session['user_id'])
        if alerts:
            for alert in alerts:
                flash(alert)

        return render_template('home.html',
                               user_name=userdata[0][1],
                               df_size=df.shape[0],
                               df=json.dumps(df.to_json()),
                               earning=earning,
                               spend=spend,
                               invest=invest,
                               saving=saving,
                               monthly_data=monthly_data,
                               card_data=card_data,
                               goals=goals,
                               table_data=table_data[-5:],
                               bar=json.dumps(bar),
                               line=json.dumps(line),
                               stack_bar=json.dumps(stack_bar),
                               pie1=json.dumps(pie1),
                               pie2=json.dumps(pie2),
                               pie3=json.dumps(pie3),
                               pie4=json.dumps(pie4),
                               pie5=json.dumps(pie5),
                               pie6=json.dumps(pie6),
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
            notes = request.form.get('notes')
            try:
                query = f"INSERT INTO user_expenses (user_id, pdate, expense, amount, pdescription) VALUES ({user_id}, '{date}', '{expense}', {amount}, '{notes}')"
                execute_query('insert', query)
                flash("Saved!")
            except:
                flash("Something went wrong.")
                return redirect("/home")
            return redirect('/home')
    else:
        return redirect('/')


@app.route('/home/add_income', methods=['POST'])
def add_income():
    if 'user_id' in session:
        user_id = session['user_id']
        if request.method == 'POST':
            date = request.form.get('i_date')
            income = request.form.get('income')
            details = request.form.get('details')
            try:
                query = f"INSERT INTO income (user_id, income, details, date) VALUES ({user_id}, {income}, '{details}', '{date}')"
                execute_query('insert', query)
                flash("Income Added Successfully!")
            except Exception as e:
                flash(f"Something went wrong: {e}")
                return redirect("/home")
            return redirect('/home')
    else:
        return redirect('/')


@app.route('/analysis')
def analysis():
    if 'user_id' in session:
        return render_template("analysis.html")
    else:
        return redirect('/')


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

        if name != userdata[0][1] and email != userdata[0][2] and len(email_list) == 0:
            query = f"UPDATE user_login SET username = '{name}', email = '{email}' WHERE user_id = {session['user_id']}"
            execute_query('insert', query)
            flash("Name and Email updated!")
        elif name != userdata[0][1] and email != userdata[0][2] and len(email_list) > 0:
            flash("Email already exists, try another!")
        elif name == userdata[0][1] and email != userdata[0][2] and len(email_list) == 0:
            query = f"UPDATE user_login SET email = '{email}' WHERE user_id = {session['user_id']}"
            execute_query('insert', query)
            flash("Email updated!")
        elif name == userdata[0][1] and email != userdata[0][2] and len(email_list) > 0:
            flash("Email already exists, try another!")
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
    return redirect('/login')  # Redirect to the login page


if __name__ == "__main__":
    app.run(debug=True)
