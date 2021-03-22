######################################################
#    Snort Net Viewer                                #
#    author: David Krüger                            #
#    https://github.com/david-tub/snort-net-viewer   #
######################################################
import ast
import json
import os
import pathlib
import re
from textwrap import dedent as d
from time import process_time

import dash
import dash_core_components as dcc
import dash_html_components as html
import dash_table
import networkx as nx
import numpy as np
import pandas as pd
import plotly.graph_objs as go
from colour import Color

# import the css template, and pass the css template into dash
external_stylesheets = ['https://codepen.io/chriddyp/pen/bWLwgP.css']
app = dash.Dash(__name__, external_stylesheets=external_stylesheets, suppress_callback_exceptions=True)
app.title = "Snort Net Viewer"

NODE_TO_CENTER = ''
current_nodes = None
current_edges = None
g_nodes_list = []
g_edges_list = []
flag_use_file = False  # True -> use of time ranges and slider


##############################################################################################################################################################
def network_graph(NODE_TO_CENTER):
    nodes = current_nodes
    edges = current_edges

    nodeSet = set()  # contains all IPs
    for index in range(0, len(nodes)):
        nodeSet.add(nodes['IP'][index])

    # to define the centric point of the networkx layout
    shells = []
    shell1 = []
    shell1.append(NODE_TO_CENTER)
    shells.append(shell1)
    shell2 = []
    for ele in nodeSet:
        if ele != NODE_TO_CENTER:
            shell2.append(ele)
    shells.append(shell2)

    G = nx.from_pandas_edgelist(edges, 'From IP', 'To IP', True,
                                create_using=nx.MultiDiGraph())

    nx.set_node_attributes(G, nodes.set_index('IP')['Type'].to_dict(), 'Type')
    nx.set_node_attributes(G, nodes.set_index('IP')['Ports in'].to_dict(), 'Ports in')
    nx.set_node_attributes(G, nodes.set_index('IP')['Ports out'].to_dict(), 'Ports out')
    # pos = nx.layout.spring_layout(G)
    # pos = nx.layout.circular_layout(G)
    # pos = nx.layout.spiral_layout(G)
    if len(shell2) > 1:
        pos = nx.drawing.layout.shell_layout(G, shells)
    else:
        pos = nx.drawing.layout.spring_layout(G)
    for node in G.nodes:
        G.nodes[node]['pos'] = list(pos[node])

    if len(shell2) == 0:
        traceRecode = []  # contains edge_trace, node_trace, middle_node_trace

        node_trace = go.Scatter(x=tuple([1]), y=tuple([1]), text=tuple([str(NODE_TO_CENTER)]),
                                textposition="bottom center",
                                mode='markers+text',
                                marker={'size': 50, 'color': 'LightSkyBlue'})
        traceRecode.append(node_trace)

        node_trace1 = go.Scatter(x=tuple([1]), y=tuple([1]),
                                 mode='markers',
                                 marker={'size': 50, 'color': 'LightSkyBlue'},
                                 opacity=0)
        traceRecode.append(node_trace1)

        figure = {
            "data": traceRecode,
            "layout": go.Layout(title='Snort Net Viewer', showlegend=False,
                                margin={'b': 40, 'l': 40, 'r': 40, 't': 40},
                                xaxis={'showgrid': False, 'zeroline': False, 'showticklabels': False},
                                yaxis={'showgrid': False, 'zeroline': False, 'showticklabels': False},
                                height=600
                                )}
        return figure

    traceRecode = []  # contains edge_trace, node_trace, middle_node_trace
    ############################################################################################################################################################
    # TODO - color range according to the attack priorities??
    colors = list(Color('black').range_to(Color('black'), len(G.edges())))
    colors = ['rgb' + str(x.rgb) for x in colors]
    index = 0
    for edge in G.edges:
        x0, y0 = G.nodes[edge[0]]['pos']
        x1, y1 = G.nodes[edge[1]]['pos']

        weight = float(G.edges[edge]['Weight']) / max(edges['Weight']) * 8
        # ensure minimal weight
        if weight < 1:
            weight = 2

        trace = go.Scatter(x=tuple([x0, x1, None]), y=tuple([y0, y1, None]),
                           mode='lines',
                           line={'width': weight},
                           marker=dict(color=colors[index]),
                           line_shape='spline',
                           opacity=1)
        traceRecode.append(trace)
        index = index + 1
    ###############################################################################################################################################################
    node_trace = go.Scatter(x=[], y=[], hovertext=[], text=[], mode='markers+text', textposition="bottom center",
                            hoverlabel_align='left',
                            hoverinfo="text", marker={'size': 50, 'color': []})

    index = 0
    for node in G.nodes():
        x, y = G.nodes[node]['pos']
        hovertext = "<b>IP Address:</b> " + str(nodes['IP'][index]) + "<br>" + "<b>Type:</b> " + \
                    str(G.nodes[node]['Type']) + "<br>" + '<b>Ports out:</b> ' + values_as_string(
            G.nodes[node]['Ports out'], 5) \
                    + "<br>" + '<b>Ports in:</b> ' + values_as_string(G.nodes[node]['Ports in'], 5)
        text = nodes['IP'][index]
        node_trace['x'] += tuple([x])
        node_trace['y'] += tuple([y])
        node_trace['hovertext'] += tuple([hovertext])
        node_trace['text'] += tuple([text])
        if str(G.nodes[node]['Type']) == 'Attacker':
            node_trace['marker']['color'] += tuple(['red'])
        elif str(G.nodes[node]['Type']) == 'Victim':
            node_trace['marker']['color'] += tuple(['green'])
        else:
            node_trace['marker']['color'] += tuple(['yellow'])
        index = index + 1

    traceRecode.append(node_trace)
    ################################################################################################################################################################
    middle_hover_trace = go.Scatter(x=[], y=[], hovertext=[], mode='markers', hoverinfo="text",
                                    marker={'size': 32, 'color': []},
                                    opacity=0, hoverlabel_align='left')

    index = 0
    for edge in G.edges:
        x0, y0 = G.nodes[edge[0]]['pos']
        x1, y1 = G.nodes[edge[1]]['pos']

        # generate good looking hover text
        attack_string = values_as_string(G.edges[edge]['Attack Name'], 2)
        class_string = values_as_string(G.edges[edge]['Classification'], 2)
        prio_string = values_as_string(G.edges[edge]['Priority'], 2)
        from_ip_string = str(G.edges[edge]['From IP'])
        from_ports_string = str(G.edges[edge]['From Ports'])
        to_ip_string = str(G.edges[edge]['To IP'])
        to_ports_string = str(G.edges[edge]['To Ports'])
        count_string = values_as_string(G.edges[edge]['Count'], 2)
        timestamps_string = values_as_string(G.edges[edge]['Timestamps'], 2)

        # hovertext = "<b>Attacks:</b> " + attack_string + "<br>" + "<b>Classifications:</b> " + class_string + "<br>" + \
        #             "<b>Priorities:</b> " + prio_string + "<br>" + "<b>From IP:</b> " + from_ip_string + "<br>" + \
        #             "<b>To IP:</b> " + to_ip_string + "<br>" + "<b>Number of Alerts:</b> " + count_string + \
        #             "<br>" + "<br>" + "<i>click to see more information in the table</i>"

        hovertext = "<b>Number of Attacks:</b> " + str(len(G.edges[edge]['Attack Name'])) + "<br>" + \
                    "<b>Number of Alerts:</b> " + str(G.edges[edge]['Weight']) + "<br>" + \
                    "<b>Highest Priority:</b> " + str(max(G.edges[edge]['Priority'])) + "<br>" +\
                    "<br>" + "<i>click to see more information in the table below</i>"

        middle_hover_trace['x'] += tuple([(x1*3 + x0) / 4])
        middle_hover_trace['y'] += tuple([(y1*3 + y0) / 4])
        middle_hover_trace['hovertext'] += tuple([hovertext])

        if isinstance(middle_hover_trace['customdata'], type(None)):
            middle_hover_trace['customdata'] = []
        customdata = np.array(list(G.edges[edge].items()), dtype=object)
        middle_hover_trace['customdata'] += tuple([customdata])

        if '1' in G.edges[edge]['Priority']:
            middle_hover_trace['marker']['color'] += tuple(['#ffe6e6'])
        elif '2' in G.edges[edge]['Priority']:
            middle_hover_trace['marker']['color'] += tuple(['#fff9e6'])
        else:
            middle_hover_trace['marker']['color'] += tuple(['white'])
        index = index + 1

    traceRecode.append(middle_hover_trace)
    #################################################################################################################################################################
    figure = {
        "data": traceRecode,
        "layout": go.Layout(title='Interactive IDS Alert Visualization', showlegend=False, hovermode='closest',
                            margin={'b': 40, 'l': 40, 'r': 40, 't': 40},
                            xaxis={'showgrid': False, 'zeroline': False, 'showticklabels': False},
                            yaxis={'showgrid': False, 'zeroline': False, 'showticklabels': False},
                            height=800,
                            clickmode='event',
                            annotations=[
                                dict(
                                    ax=(G.nodes[edge[0]]['pos'][0] + G.nodes[edge[1]]['pos'][0]) / 2,
                                    ay=(G.nodes[edge[0]]['pos'][1] + G.nodes[edge[1]]['pos'][1]) / 2, axref='x',
                                    ayref='y',
                                    x=(G.nodes[edge[1]]['pos'][0] * 3 + G.nodes[edge[0]]['pos'][0]) / 4,
                                    y=(G.nodes[edge[1]]['pos'][1] * 3 + G.nodes[edge[0]]['pos'][1]) / 4, xref='x',
                                    yref='y',
                                    showarrow=True,
                                    arrowhead=3,
                                    arrowsize=5,
                                    arrowwidth=1,
                                    opacity=1
                                ) for edge in G.edges]
                            )}
    return figure


def values_as_string(listo, num):
    my_string = ""
    for index, value in enumerate(listo):
        if index == 0:
            # first element
            my_string = str(value)
        elif 1 <= index < num:
            # not the first element and still in range
            my_string += ", " + str(value)
        else:
            # still elements there but limit reached
            my_string += ", ..."
            break
    return my_string

def pretty_time_delta(my_timedelta):
    seconds = my_timedelta.total_seconds()
    seconds = abs(int(seconds))
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes, seconds = divmod(seconds, 60)
    if days > 0:
        return '%dd %dh %dm %ds' % (days, hours, minutes, seconds)
    elif hours > 0:
        return '%dh %dm %ds' % (hours, minutes, seconds)
    elif minutes > 0:
        return '%dm %ds' % (minutes, seconds)
    else:
        return '%ds' % (seconds)

######################################################################################################################################################################



def build(nodes=None, nodes_file=None, edges=None, edges_file=None, alert_file=None, time_ranges=None, timer_start=process_time()):
    """
    builds the server (html, callbacks etc.)
    :param nodes: if existing: list of dicts of nodes (display-only)
    :param nodes_file: if existing: nodes csv file to read and display (export-display, import-display)
    :param edges: if existing: list of dicts of edges (display-only)
    :param edges_file: if existing: edges csv file to read and display (export-display, import-display)
    :param alert_file: if existing: csv file which needs to be loaded (display-only)
    :param time_ranges: if existing: list of time ranges/steps for filter component
    """
    print('[*] Start building the server')
    # for debug purpose: increase display range of dicts
    pd.set_option("display.max_rows", None, "display.max_columns", None)

    global NODE_TO_CENTER
    global flag_use_file
    global current_nodes
    global current_edges
    global g_nodes_list
    global g_edges_list

    alert_file_name = '-'
    nodes_file_name = '-'
    edges_file_name = '-'
    # get file names (just as general information)
    if isinstance(alert_file, pathlib.Path):
        alert_file_name = os.path.basename(alert_file)
    if isinstance(nodes_file, pathlib.Path):
        nodes_file_name = os.path.basename(nodes_file)
    if isinstance(edges_file, pathlib.Path):
        edges_file_name = os.path.basename(edges_file)

    if not isinstance(nodes_file, type(None)) and not isinstance(edges_file, type(None)):
        # load data from files
        nodes = pd.read_csv(nodes_file)
        edges = pd.read_csv(edges_file)

        # convert string values to real lists
        nodes['Ports in'] = nodes['Ports in'].apply(lambda x: ast.literal_eval(x))
        nodes['Ports out'] = nodes['Ports out'].apply(lambda x: ast.literal_eval(x))

        edges['Attack Name'] = edges['Attack Name'].apply(lambda x: ast.literal_eval(x))
        edges['Classification'] = edges['Classification'].apply(lambda x: ast.literal_eval(x))
        edges['Priority'] = edges['Priority'].apply(lambda x: ast.literal_eval(x))
        edges['From Ports'] = edges['From Ports'].apply(lambda x: ast.literal_eval(x))
        edges['To Ports'] = edges['To Ports'].apply(lambda x: ast.literal_eval(x))
        edges['Timestamps'] = edges['Timestamps'].apply(lambda x: ast.literal_eval(x))
        edges['Count'] = edges['Count'].apply(lambda x: ast.literal_eval(x))
        edges['Additional'] = edges['Additional'].apply(lambda x: ast.literal_eval(x))

        g_nodes_list = [nodes]
        g_edges_list = [edges]
        current_nodes = nodes
        current_edges = edges

        # set flag for easy use
        flag_use_file = True
    else:
        # check for valid time_ranges
        if not isinstance(time_ranges, list) or len(time_ranges) == 0:
            print('[*]ERROR: Invalid time ranges')
            exit(-1)
        # load given data (nodes = list of list of nodes)
        g_nodes_list = nodes
        g_edges_list = edges
        current_nodes = nodes[-1]
        current_edges = edges[-1]

        print('[**] Number of Nodes: ' + str(len(current_nodes)))
        print('[**] Number of Edges: ' + str(len(current_edges)))

        # print(str(current_nodes))
        # print(str(current_edges))
        flag_use_file = False

    if not flag_use_file:
        # format the time range
        time_range_dataset = time_ranges[len(time_ranges) - 1] - time_ranges[0]
        time_range_dataset = pretty_time_delta(time_range_dataset)
    else:
        # no time range
        time_range_dataset = '-'


    # calculate some general information
    sum_alerts = 0
    sum_attacks = 0
    for column, rows in current_edges.items():
        for index, value in enumerate(rows):
            if column == 'Attack Name':
                sum_attacks += len(value)
            elif column == 'Weight':
                sum_alerts += value

    ##time_range_dataset_str = time_range_dataset.strftime("%d-%H:%M:%S")

    ######### building html components

    # build columns and rename column names
    columns = []
    for key in current_edges.columns:
        if key != "Weight" and key != "Attack Direction":
            if key == "Timestamps":
                name = "First and last timestamp"
            elif key == "Count":
                name = "Number Alerts"
            elif key == "Additional":
                name = "Additional Information"
            else:
                name = key
            columns.append(
                {
                    "name": name,
                    "id": key,
                    "presentation": "markdown"
                }
            )

    # marks for the slider
    if not flag_use_file:
        marks = {}
        for index, time in enumerate(time_ranges):
            new_str = time_ranges[index].strftime("%Y/%m/%d-%H:%M:%S")
            marks[index] = {'label': new_str}

    # children for left side components
    children_left_side = []
    if not flag_use_file:
        # markdown text for range slider
        children_left_side.append(dcc.Markdown(d("""
                **Time Range To Visualize**

                Select the time range to be visualized.
                """)))
        # range slider
        children_left_side.append(html.Div(
            className="twelve columns",
            children=[
                dcc.Slider(
                    id='my-slider',
                    min=0,
                    max=len(time_ranges) - 1,
                    step=None,
                    value=len(time_ranges) - 1,
                    marks=marks,
                    vertical=True,
                ),
                html.Br(),
                html.Div(id='output-container-slider'),
            ],
            style={'height': '500px'}
        ))
    else:
        # dummy slider (for modes export-display, import-display)
        # invisible but needed to get the callbacks running
        # (dash demands one callback for both "node to center" and "slider", we dont need slider in some modes so we have to create dummy slider to avoid error)
        children_left_side.append(html.Div(
            className="twelve columns",
            children=[dcc.Slider(
                id='my-slider',
                min=-0,
                max=0,
                step=0,
                value=0
            )
            ],
            style={'display': 'none'}
        ))

    # markdown text for node to center
    children_left_side.append(html.Div(
        className="twelve columns",
        children=[
            dcc.Markdown(d("""
                    **Node to Center**

                    Input IP to center the corresponding Node.
                    """)),
            dcc.Input(id="input1", type="text", placeholder="Account"),
            html.Div(id="output")
        ],
        style={'height': '300px'}
    ))

    app.layout = html.Div([
        ######### Title
        html.Div([html.H1("Snort Net Viewer")],
                 className="row",
                 style={'textAlign': "center"}),
        ######### define the row
        html.Div(
            className="row",
            children=[
                ######### left side two input components
                html.Div(
                    className="two columns",
                    children=children_left_side,
                ),

                ######### middle graph component
                html.Div(
                    className="eight columns",
                    children=[dcc.Graph(id="my-graph",
                                        figure=network_graph(NODE_TO_CENTER))],
                ),
                ######### right side two output component
                html.Div(
                    className="two columns",
                    children=[
                        html.Div(
                            className='twelve columns',
                            children=[
                                dcc.Markdown(d(f"""
                                **General Dataset Information**  
                                
                                Imported log file: &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;*{str(alert_file_name)}*  
                                CSV nodes file: &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;*{str(nodes_file_name)}*  
                                CSV edges file: &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;*{str(edges_file_name)}*  
                                Processing time: &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;*{str(round(process_time()-timer_start,3)) + ' s'}*  

                                Number of nodes: &nbsp; &nbsp; &nbsp; &nbsp;*{str(len(current_nodes))}*  
                                Number of edges: &nbsp; &nbsp; &nbsp; &nbsp;*{str(len(current_edges))}*  

                                Time range: &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;*{str(time_range_dataset)}*  
                                Number of attacks: &nbsp; &nbsp; &nbsp;*{str(sum_attacks)}*  
                                Number of alerts: &nbsp; &nbsp; &nbsp; &nbsp;*{str(sum_alerts)}*  
                                """
                                               )),
                            ],

                            style={'height': '350px'}),

                        html.Div(
                            className='twelve columns',
                            children=[
                                dcc.Markdown(d("""
                                **Click Data**
    
                                Click on nodes and edges in the graph to see advanced data.
                                """)),
                                html.Pre(id='click-data', style={
                                    'border': 'thin lightgrey solid',
                                    'overflowX': 'scroll',
                                    'height': '400px',
                                })
                            ],
                            style={'height': '450px'})
                    ]
                )
            ]
        ),
        html.Div(
            className='row',
            children=[
                html.Div(
                    className='row',
                    children=[
                        dcc.Markdown(d("""
                        **Attack Details**

                        Click on an edge to see all related attack information in the table.
                        """)),
                    ],
                    style={'textAlign': "center"}),
                html.Div(
                    className="row",
                    children=[dash_table.DataTable(
                        id='my_table',
                        columns=[c for c in columns],
                        filter_action="native",
                        sort_action="native",
                        data=current_edges.to_dict('records'),
                        style_header={
                            'fontWeight': 'bold',
                            'textAlign': 'left',
                        },
                        style_cell={
                            'textAlign': 'left',
                            'whiteSpace': 'normal',
                            'height': 'auto',
                        },
                        style_data_conditional=[
                            {'if': {'filter_query': '{Priority} = 1'},
                             'backgroundColor': '#ffe6e6'},
                            {'if': {'filter_query': '{Priority} = 2'},
                             'backgroundColor': '#fff9e6'},

                            {'if': {'column_id': 'Attack Name'},
                             'width': '15%'},
                            {'if': {'column_id': 'Classification'},
                             'width': '10%'},
                            {'if': {'column_id': 'Priority'},
                             'width': '5%'},
                            {'if': {'column_id': 'From IP'},
                             'width': '5%'},
                            {'if': {'column_id': 'To IP'},
                             'width': '5%'},
                            {'if': {'column_id': 'From Ports'},
                             'width': '10%'},
                            {'if': {'column_id': 'To Ports'},
                             'width': '10%'},
                            {'if': {'column_id': 'Timestamps'},
                             'width': '20%'},
                            {'if': {'column_id': 'Count'},
                             'width': '5%'},
                            {'if': {'column_id': 'Additional'},
                             'width': '15%'},
                        ]
                    )],
                    style={'margin-bottom': 10},
                ),
            ],
        )
    ])

    # TODO - error in export-display mode because first input does not exists - solution? - dash callbacks dynamic input ?
    ######### callback for the time range slider and the node center input component
    @app.callback(
        dash.dependencies.Output('my-graph', 'figure'),
        [dash.dependencies.Input('my-slider', 'value'), dash.dependencies.Input('input1', 'value')])
    def update_time_range_and_node_to_center(value, input1):
        global current_nodes
        global current_edges
        global NODE_TO_CENTER
        current_nodes = g_nodes_list[value]
        current_edges = g_edges_list[value]
        NODE_TO_CENTER = input1
        blank_row = {}
        for column in columns:
            blank_row[column['id']] = ''
        return network_graph(NODE_TO_CENTER)

    ######### callback for the click data component
    @app.callback(
        dash.dependencies.Output('click-data', 'children'),
        [dash.dependencies.Input('my-graph', 'clickData')])
    def display_click_data(clickData):
        if clickData:
            return json.dumps(clickData, indent=2)

    ######### callback for the table component
    @app.callback(
        dash.dependencies.Output('my_table', 'data'),
        [dash.dependencies.Input('my-graph', 'clickData'), dash.dependencies.Input('my_table', 'columns')])
    def display_click_data_in_table(clickData, columns):
        if not clickData or 'customdata' not in clickData['points'][0]:
            # just show blank row
            blank_row = {}
            for column in columns:
                blank_row[column['id']] = ''
            return [blank_row]
        else:
            current_edge = clickData['points'][0]['customdata']
            return edge_to_dicts_for_table(current_edge)

    def edge_to_dicts_for_table(edge):
        """
        generates a list of dicts from a single edge
        :param edge:
        :return: list of dicts to display them in the table
        """
        list_of_dicts = []
        num_attacks = len(edge[0][1])

        for i in range(num_attacks):
            dict = {}
            for index, pairs in enumerate(edge):
                if not isinstance(pairs[1], list):
                    # single data like IP or Weight
                    dict[pairs[0]] = str(pairs[1])
                elif pairs[0] == 'Additional':
                    # format links to clickable
                    dict[pairs[0]] = build_markdown_links(pairs[1][i])
                else:
                    # list data like attack names or ports
                    # format string for better look
                    dict[pairs[0]] = str(pairs[1][i]).replace('[', '').replace(']', '').replace('\'', '')


            list_of_dicts.append(dict)

        # go over lines to swap from_ip and to_ip where direction is opposite
        for index, dicto in enumerate(list_of_dicts):
            if dicto["Attack Direction"] == str(1):
                # swap IPs
                from_ip = dicto["To IP"]
                to_ip = dicto["From IP"]
                # write back to list
                list_of_dicts[index]["From IP"] = from_ip
                list_of_dicts[index]["To IP"] = to_ip

        return list_of_dicts

    def build_markdown_links(my_list):
        """
        extract links from a string and build clickable markdown links
        :param my_list: list in which the given string is
        :return: string with markdown links
        """
        all_links = re.findall(r'http:.*?\].*?', my_list[0])

        new = ''
        for link in all_links:
            # html_my = html.A(html.P('Link'), href=link[:-1])
            my_link = '[' + link[:-1] + '"](' + link[
                                                :-1] + ")"  # cut the last character because "]" is still in the string
            new += '  ' + my_link  # two whitspaces means line break in markdown

        # example = ['[Stack Overflow](http://stackoverflow.com)', '[Stack Overflow](http://stackoverflow.com)']
        return new

    print('[*] Server build successfully')
