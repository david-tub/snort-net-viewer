# SnortNetViewer
**Interactive network visualization for intrusion detection build on NetworkX, Plotly and Dash**

The framework visualizes Snort alert log files in a node-link/network diagram. It provides several interactive features to explore the information extracted from the log file.

## Corresponding thesis and introduction video
This project is part of the Master Thesis "Interactive Network Visualization for Intrusion Detection" by David Krüger at the DAI Labor at the TU Berlin in winter term 2020/2021.

An introduction video of the visualization framework can be found here:\
https://www.youtube.com/watch?v=nQUacQPlF5w


## Usage
usage: main.py [-h] [--mode {export-only,export-display,import-display,display-only}] [--file_path FILE_PATH] [--time_ranges TIME_RANGES] [--nodes_file_path NODES_FILE_PATH] [--edges_file_path EDGES_FILE_PATH]


### Modes and example usage
**1. export-only**
- Reads a Snort alert log file and exports the nodes and edges as CSV files (root folder: edges.csv and nodes.csv)
- Example: _main.py --mode export-only --file_path exampleLogs\wannaCry\alert_

**2. display-only**
- Reads a Snort alert log file and visualizes it in the framework web interface
- Example: _main.py --mode display-only --file_path exampleLogs\wannaCry\alert --time_ranges 5_

**3. export-display**
- Reads a Snort alert log file, exports the nodes and edges as CSV files, and visualizes it in the framework web interface
- Example: _main.py --mode export-display --file_path exampleLogs\wannaCry\alert --time_ranges 5_

**4. import-display**
- Reads two CSV files containing the nodes and edges and visualizes them in the framework web interface
- Example: _main.py --mode import-display --nodes_file nodes.csv --edges_file edges.csv_


## Additional Material
The framework was evaluated through a student survey on cybersecurity visualization. The Survey form and the results in the form of a report can be found in the "survey" subfolder.

Example alert log files can be found in the "exampleLogs" subfolder.