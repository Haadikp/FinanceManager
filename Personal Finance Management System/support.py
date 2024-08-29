import datetime
import pandas as pd
import pymysql
import plotly
import plotly.express as px
import json

# Database connection setup (replace with your actual database credentials)
def connect_db():
    conn = pymysql.connect(
        host="localhost",      # Your database host, usually "localhost"
        user="root",           # Your database user
        password="",           # Your database password
        database="personal_finance_management_system"  # Your database name
    )
    cursor = conn.cursor()
    return conn, cursor

def close_db(connection=None, cursor=None):
    cursor.close()
    connection.close()

def execute_query(operation=None, query=None):
    connection, cursor = connect_db()
    try:
        if operation == 'search':
            cursor.execute(query)
            data = cursor.fetchall()
            return data
        elif operation == 'insert':
            cursor.execute(query)
            connection.commit()
    except Exception as e:
        print(f"Error occurred: {e}")
    finally:
        close_db(connection, cursor)

def generate_df(df):
    df['Date'] = pd.to_datetime(df['Date'])
    df['Year'] = df['Date'].dt.year
    df['Month_name'] = df['Date'].dt.month_name()
    df['Month'] = df['Date'].dt.month
    df['Day_name'] = df['Date'].dt.day_name()
    df['Day'] = df['Date'].dt.day
    df['Week'] = df['Date'].dt.isocalendar().week
    return df

def num2MB(num):
    if num < 1000:
        return int(num)
    if 1000 <= num < 1000000:
        return f'{float("%.2f" % (num / 1000))}K'
    elif 1000000 <= num < 1000000000:
        return f'{float("%.2f" % (num / 1000000))}M'
    else:
        return f'{float("%.2f" % (num / 1000000000))}B'

def top_tiles(df=None):
    if df is not None:
        tiles_data = df[['Expense', 'Amount']].groupby('Expense').sum()
        tiles = {'Earning': 0, 'Investment': 0, 'Saving': 0, 'Spend': 0}
        for i in list(tiles_data.index):
            try:
                tiles[i] = num2MB(tiles_data.loc[i][0])
            except:
                pass
        return tiles['Earning'], tiles['Spend'], tiles['Investment'], tiles['Saving']
    return

def generate_Graph(df=None):
    if df is not None and df.shape[0] > 0:
        bar_data = df[['Expense', 'Amount']].groupby('Expense').sum().reset_index()
        bar = px.bar(x=bar_data['Expense'], y=bar_data['Amount'], color=bar_data['Expense'], template="plotly_dark",
                     labels={'x': 'Expense Type', 'y': 'Balance (₹)'}, height=287)
        bar.update(layout_showlegend=False)
        bar.update_layout(
            margin=dict(l=2, r=2, t=40, b=2),
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)')

        s = df.groupby(['Note', 'Expense']).sum().reset_index()
        stack = px.bar(x=s['Note'], y=s['Amount'], color=s['Expense'], barmode="stack", template="plotly_dark",
                       labels={'x': 'Category', 'y': 'Balance (₹)'}, height=290)
        stack.update(layout_showlegend=False)
        stack.update_xaxes(tickangle=45)
        stack.update_layout(
            margin=dict(l=2, r=2, t=30, b=2),
            paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)'
        )

        line = px.line(df, x='Date', y='Amount', color='Expense', template="plotly_dark")
        line.update_xaxes(rangeslider_visible=True)
        line.update_layout(title_text='Track Record', title_x=0.,
                           legend=dict(
                               orientation="h",
                               yanchor="bottom",
                               y=1.02,
                               xanchor="right",
                               x=1
                           ),
                           margin=dict(l=2, r=2, t=30, b=2),
                           paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)'
                           )

        pie = px.sunburst(df, path=['Expense', 'Note'], values='Amount', height=280, template="plotly_dark")
        pie.update_layout(margin=dict(l=0, r=0, t=0, b=0),
                          paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)')

        bar = json.dumps(bar, cls=plotly.utils.PlotlyJSONEncoder)
        pie = json.dumps(pie, cls=plotly.utils.PlotlyJSONEncoder)
        line = json.dumps(line, cls=plotly.utils.PlotlyJSONEncoder)
        stack_bar = json.dumps(stack, cls=plotly.utils.PlotlyJSONEncoder)

        return bar, pie, line, stack_bar
    return None

def makePieChart(df=None, expense='Earning', names='Note', values='Amount', hole=0.5,
                 color_discrete_sequence=px.colors.sequential.RdBu, size=300, textposition='inside',
                 textinfo='percent+label', margin=2):
    fig = px.pie(df[df['Expense'] == expense], names=names, values=values, hole=hole,
                 color_discrete_sequence=color_discrete_sequence, height=size, width=size)
    fig.update_traces(textposition=textposition, textinfo=textinfo)
    fig.update_layout(annotations=[dict(text=expense, y=0.5, font_size=20, font_color='white', showarrow=False)])
    fig.update_layout(margin=dict(l=margin, r=margin, t=margin, b=margin),
                      paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)')
    fig.update(layout_showlegend=False)
    return json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

def get_monthly_data(df, year=datetime.datetime.today().year, res='int'):
    temp = pd.DataFrame()
    d_year = df.groupby('Year').get_group(year)[['Expense', 'Amount', 'Month']]
    d_month = d_year.groupby("Month")
    for month in list(d_month.groups.keys())[::-1][:3]:
        dexp = d_month.get_group(month).groupby('Expense').sum().reset_index()
        for row in range(dexp.shape[0]):
            temp = temp.append(
                dict({"Expense": dexp.iloc[row]['Expense'], "Amount": dexp.iloc[row]['Amount'], "Month": month}),
                ignore_index=True)
    month_name = {1: 'January', 2: 'February', 3: 'March', 4: 'April', 5: 'May', 6: 'June', 7: "July", 8: 'August',
                  9: "September", 10: "October", 11: "November", 12: "December"}
    ls = []
    for month in list(d_month.groups.keys())[::-1][:3]:
        m = {}
        s = temp[temp['Month'] == month]
        m['Month'] = month_name[month]
        for i in range(s.shape[0]):
            if res == 'int':
                m[s.iloc[i]['Expense']] = int(s.iloc[i]['Amount'])
            else:
                m[s.iloc[i]['Expense']] = num2MB(int(s.iloc[i]['Amount']))
        ls.append(m)
    return ls

def sort_summary(df):
    datas = []

    h_month, h_year, h_amount = [], [], []
    for year in list(df['Year'].unique()):
        d = df[df['Year'] == year]
        data = d[d['Expense'] == 'Earning'].groupby("Month_name").sum()['Amount'].reset_index().sort_values("Amount",
                                                                                                            ascending=False).iloc[
            0]
        h_month.append(data['Month_name'])
        h_year.append(year)
        h_amount.append(data['Amount'])
    amount = max(h_amount)
    month = h_month[h_amount.index(amount)]
    year = h_year[h_amount.index(amount)]
    datas.append(
        {'head': "₹" + str(num2MB(amount)), 'main': f"{month}  {year}", 'label': "Highest Income Month"})

    h_date, h_amount = [], []
    for date in list(df['Date'].unique()):
        d = df[df['Date'] == date]
        h_amount.append(d['Amount'].sum())
        h_date.append(date)
    amount = max(h_amount)
    date = h_date[h_amount.index(amount)].strftime("%d-%m-%Y")
    datas.append(
        {'head': "₹" + str(num2MB(amount)), 'main': f"{date}", 'label': "Highest Income Day"})

    amount = df[df['Expense'] == 'Earning']['Amount'].mean()
    datas.append(
        {'head': "₹" + str(num2MB(amount)), 'main': "", 'label': "Average Daily Income"})

    amount = df[df['Expense'] == 'Spend'].mean()['Amount']
    datas.append(
        {'head': "₹" + str(num2MB(amount)), 'main': "", 'label': "Average Daily Spend"})

    amount = df[df['Expense'] == 'Saving'].mean()['Amount']
    datas.append(
        {'head': "₹" + str(num2MB(amount)), 'main': "", 'label': "Average Daily Saving"})

    amount = df[df['Expense'] == 'Investment'].mean()['Amount']
    datas.append(
        {'head': "₹" + str(num2MB(amount)), 'main': "", 'label': "Average Daily Investment"})

    return datas

def expense_goal(df):
    goals = []
    data = df[df['Expense'] == 'Spend'].groupby('Note').sum()['Amount'].reset_index().sort_values('Amount',
                                                                                                  ascending=False)
    for i in range(min(3, data.shape[0])):
        goals.append(dict(Task=data.iloc[i]['Note'], Done=data.iloc[i]['Amount']))
    return goals
