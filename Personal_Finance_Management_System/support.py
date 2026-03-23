import pandas as pd
import plotly.express as px
import json

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
    return 0, 0, 0, 0

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
        return bar, pie, line, stack
    return None, None, None, None

def get_monthly_data(df, res=None):
    if df is not None:
        # Process data for monthly overview
        monthly_data = df.groupby(['Year', 'Month_name']).sum()['Amount'].reset_index()
        return monthly_data
    return []

def sort_summary(df):
    if df is not None:
        summary = df.groupby(['Note']).sum().sort_values('Amount', ascending=False).reset_index()
        return summary.to_dict(orient='records')
    return []

def expense_goal(df):
    if df is not None:
        goal = df.groupby(['Expense']).sum().reset_index()
        return goal.to_dict(orient='records')
    return []

def makePieChart(df, column, group_by, size=240):
    if df is not None:
        pie = px.pie(df, names=group_by, values=column, hole=0.3, template="plotly_dark", height=size)
        pie.update_traces(textposition='inside', textinfo='percent+label')
        pie.update_layout(margin=dict(l=0, r=0, t=0, b=0),
                          paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)')
        return json.dumps(pie, cls=plotly.utils.PlotlyJSONEncoder)
    return None
