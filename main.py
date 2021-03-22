#############################################################
#            SnortNetViewer                               #
#            author: David Krüger                           #
#            https://github.com/david-tub/snort-net-viewer  #
#############################################################

import snortparser as my_parser
import server as my_server
import argparse
from pathlib import Path
from time import process_time

if __name__ == '__main__':
    # parse program arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", dest='mode', help='one of the allowed modes',
                        choices=['export-only', 'export-display', 'import-display', 'display-only'], required=True)
    parser.add_argument("--file_path", dest='file_path', type=Path, help='path to snort log file', required=False)
    parser.add_argument("--time_ranges", dest='time_ranges',
                        help='needed for mode display-only: number of time ranges (min=2)', type=int,
                        required=False)
    parser.add_argument("--nodes_file_path", dest='nodes_file_path',
                        help='needed for mode import-display: path to csv file of nodes', type=Path,
                        required=False)
    parser.add_argument("--edges_file_path", dest='edges_file_path',
                        help='needed for mode import-display: path to csv file of edges', type=Path,
                        required=False)
    p = parser.parse_args()

    print('[*] Starting in mode: ' + p.mode)

    # start timer
    processing_start = process_time()

    # read and import log file
    if p.mode != 'import-display':
        read = my_parser.read_log_file(p.file_path)
        imported = my_parser.import_alerts(read)

    # export csv and exit
    if p.mode == 'export-only':
        # generate nodes and edges
        nodes, edges = my_parser.generate_nodes_and_edges(imported)
        # export to csv
        nodes_file, edges_file = my_parser.export_to_csv(nodes, edges)
    # export and visualize
    elif p.mode == 'export-display':
        # generate nodes and edges
        nodes, edges = my_parser.generate_nodes_and_edges(imported)
        # export to csv
        nodes_file, edges_file = my_parser.export_to_csv(nodes, edges)
        # build network and dash server (use csv files)
        my_server.build(nodes_file=nodes_file, edges_file=edges_file, alert_file=p.file_path, timer_start=processing_start)
        # start server
        print('[*] Starting the server ...')
        my_server.app.run_server(debug=False)
    # import given csv file and display
    elif p.mode == 'import-display':
        # build network and dash server
        my_server.build(nodes_file=p.nodes_file_path, edges_file=p.edges_file_path, timer_start=processing_start)
        # start server
        print('[*] Starting the server ...')
        my_server.app.run_server(debug=False)
    # 'display-only' - visualize directly without export
    # enable time range adjustment
    elif p.mode == 'display-only':
        # calculate ranges
        time_ranges = p.time_ranges
        if not isinstance(time_ranges, int) or time_ranges <= 1:
            # use default
            time_ranges = 5
        time_ranges = my_parser.calculate_time_ranges(imported, time_ranges)
        # generate nodes and edges in ranges
        # returns a list of nodes and a list of edges according to the time ranges
        nodes_list, edges_list = my_parser.generate_nodes_and_edges(imported, time_ranges)
        # build network and dash server
        my_server.build(nodes=nodes_list, edges=edges_list, time_ranges=time_ranges, alert_file=p.file_path, timer_start=processing_start)
        # start server
        print('[*] Starting the server ...')
        my_server.app.run_server(debug=False)
    else:
        print('[*] ERROR: unknown mode')
        exit(-1)

    exit(0)
