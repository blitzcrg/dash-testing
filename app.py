import dash
import dash_core_components as dcc
import dash_html_components as html
import plotly.graph_objs as go
import pandas as pd
from dash.dependencies import Input, Output

app = dash.Dash(__name__)

colors = {
    'background': 'rgb(73, 79, 89)',
    'text': 'rgb(255,255,255)'
}

# Defines the dashboard layout.
app.layout = html.Div([
    dcc.Interval(
        id='interval-component',
        interval=60*1000,
        n_intervals=0
    ),
    html.Div(
        className='row',
        children=[
            html.Div(
                className='six columns',
                children=[
                    html.Div(
                        children=dcc.Graph(id='phishing-stacked-bar')
                    )
                ]
            ),
            html.Div(
                className='six columns',
                children=[
                    html.Div(
                        children=dcc.Graph(id='threat_map'),
                    )
                ]
            ),
        ]
    ),
    html.Div(
        className='row',
        children=[
            html.Div(
                className='six columns',
                children=[
                    html.Div(
                        children=dcc.Graph(id='threats-stacked-bar'),
                    )
                ]
            )
        ]
    ),
])

# Generate or update Phishing Victims chart.
@app.callback(Output('phishing-stacked-bar', 'figure'),
              [Input('interval-component', 'n_intervals')])
def update_phishing_stacked_live(n):
    # Import data from phishing.csv (same as Threats chart, uses different
    # columns).
    data = pd.read_csv('phishing.csv')
    # Define chart columns
    data1 = go.Bar(x=data['User'],
                   y=data['ClicksPermitted'],
                   name='Clicks Permitted'
                   )

    data2 = go.Bar(x=data['User'],
                   y=data['ClicksBlocked'],
                   name='Clicks Blocked'
                   )

    figure = go.Figure(data=[data1, data2],
                       layout=go.Layout(barmode='stack',
                                        title='Phishing Victims: Last 7 Days',
                                        paper_bgcolor=colors['background'],
                                        plot_bgcolor=colors['background'],
                                        font=dict(color=colors['text']),
                                        yaxis=dict(showgrid=True,
                                                   gridcolor=colors['text']),
                                        )
                       )

    return figure

# Generate or update Threats chart.
@app.callback(Output('threats-stacked-bar', 'figure'),
              [Input('interval-component', 'n_intervals')])
def update_threats_stacked_live(n):
    # Import data from phishing.csv (same as Phishing chart, uses different
    # columns).
    data = pd.read_csv('phishing.csv')
    # Define chart columns
    data1 = go.Bar(x=data['User'],
                   y=data['Spam'],
                   name='Spam'
                   )

    data2 = go.Bar(x=data['User'],
                   y=data['Malware'],
                   name='Malware')

    data3 = go.Bar(x=data['User'],
                   y=data['Phish'],
                   name='Phishing')

    figure = go.Figure(data=[data1, data2, data3],
                       layout=go.Layout(barmode='stack',
                                        title='Phishing Threats: Last 7 Days',
                                        paper_bgcolor=colors['background'],
                                        plot_bgcolor=colors['background'],
                                        font=dict(color=colors['text']),
                                        yaxis=dict(showgrid=True,
                                                   gridcolor=colors['text']),
                                        )
                       )

    return figure


# Generate or update Attack Map.
@app.callback(Output('threat_map', 'figure'),
              [Input('interval-component', 'n_intervals')])
def update_threat_map(n):
    data = pd.read_csv('ids_threats.csv')
    data.head()

    pewpewmap = [go.Scattergeo(
        locationmode='country names',
        lon=data['longdec.src'],
        lat=data['latdec.src'],
        hoverinfo='text',
        text=data['policy.name'],
        mode='markers',
        marker=go.scattergeo.Marker(
            size=2,
            line=go.scattergeo.marker.Line(
                    width=3
                )
            )
        )
    ]

    attack_paths = []
    for i in range(len(data)):
        attack_paths.append(
            go.Scattergeo(
                locationmode='country names',
                lon=[data['longdec.src'][i], -114.0708],
                lat=[data['latdec.src'][i], 51.0486],
                mode='lines',
                line=go.scattergeo.Line(
                    width=2,
                ),
                opacity=1,
            )
        )

    layout = go.Layout(
        title=go.layout.Title(
            text='IDS/IPS Signature Hits: Last 24 Hours'
        ),
        paper_bgcolor=colors['background'],
        plot_bgcolor=colors['background'],
        font=dict(color=colors['text']),
        showlegend=False,
        geo=go.layout.Geo(
            scope='world',
            resolution=50,
            projection=go.layout.geo.Projection(type="equirectangular"),
            showland=True,
            showocean=True,
            oceancolor=colors['background'],
            landcolor='rgb(200, 200, 200)',
            showcountries=True,
            lonaxis=go.layout.geo.Lonaxis(
                range=[-294.0708, 65.9292],
                dtick=10
            ),
        ),
    )

    figure = go.Figure(data=attack_paths + pewpewmap, layout=layout)
    return figure


if __name__ == '__main__':
    app.run_server(debug=True)
