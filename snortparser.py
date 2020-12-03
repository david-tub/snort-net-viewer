import json
import re
import pandas as pd
import datetime
import time
import copy

current_min_number_alerts = 0  # minimal number of an alert
current_max_number_alerts = 0  # maximal number of an alert
EDGE_WEIGHT_SCALING_MIN = 1  # scaled width of the edges
EDGE_WEIGHT_SCALING_MAX = 10

TYPE_ATTACKER = 'Attacker'
TYPE_VICTIM = 'Victim'
TYPE_COMPROMISED = 'Compromised'


class Alert:
    name = None
    classification = None
    priority = None
    from_ip = None
    to_ip = None
    timestamp = None

    from_port = ""
    to_port = ""
    additional = ""

    def validate(self):
        if self.name and self.classification and self.priority and self.from_ip and self.to_ip and self.timestamp:
            return True
        else:
            return False


def read_log_file(file_path):
    """
    Read log file and create a list of alerts (strings)
    :param file_path: file path of the Snort log file (alert)
    :return: list of list of strings (list of alerts consists of the lines)
    """
    print('[*] Start reading the log file')
    all_alerts = []  # all alerts, list of alerts consists of all lines

    with open(file_path, 'r') as current:
        lines = current.readlines()
        if not lines:
            print('FILE IS EMPTY')
            return -1
        else:
            # load alerts one by one
            alert = []  # new alert
            for line in lines:
                if line.startswith('[**]'):
                    # new alert
                    if len(alert) != 0:
                        all_alerts.append(alert)
                    alert = [line.strip('\n')]
                elif line != '\n':
                    # line belongs to the same alert
                    alert.append(line.strip('\n'))
            # add last alert to list
            all_alerts.append(alert)
    print('[*] Log file successfully read')
    return all_alerts


def import_alerts(all_alerts):
    """
    Go over all_alerts list and extract details to create Alert objects
    :param all_alerts: list of list of strings
    :return: list of validated alerts (list of alert objects)
    """
    print('[*] Start importing alerts')
    alerts_validated = []
    alerts_corrupted = []

    for alert in all_alerts:
        alert_obj = Alert()
        # m = re.search(r'(\b[a-zA-Z -]+\b)', alert[0])
        m = re.search(r'\[\*\*\].*\[(.*?)\](.*?)\[\*\*\]', alert[0])
        if m:
            alert_obj.name = m.group(2).strip()

        m = re.search(r'\[Classification: (\b[a-zA-Z -]+\b)\].\[Priority: ([1-9])\]', alert[1])
        if m:
            alert_obj.classification = m.group(1).strip()
            alert_obj.priority = m.group(2).strip()

        m = re.search(
            r'([0-9/]+-[0-9:.]+)\s+.*?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5})\s+->\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5})',
            alert[2])
        if not m:
            m = re.search(
                r'([0-9/]+-[0-9:.]+)\s+.*?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+->\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
                alert[2])
            if m:
                alert_obj.timestamp = str(datetime.datetime.now().year) + '/' + m.group(1).strip()
                alert_obj.from_ip = m.group(2).strip()
                alert_obj.to_ip = m.group(3).strip()
                # print('Date: ' + m.group(1) + ' Time: ' + m.group(2) + ' FromIP: ' + m.group(3) + ' ToIP: ' + m.group(4))
        else:
            alert_obj.timestamp = str(datetime.datetime.now().year) + '/' + m.group(1).strip()
            alert_obj.from_ip = m.group(2).strip()
            alert_obj.from_port = m.group(3).strip()
            alert_obj.to_ip = m.group(4).strip()
            alert_obj.to_port = m.group(5).strip()

        # lines 3 and 4 contain packet information
        # because every line will be unique, we will leave it out

        # if 3 < len(alert):
        #     alert_obj.additional = alert[3]

        # if 4 < len(alert):
        #     alert_obj.additional += '\n' + alert[4]

        if 5 < len(alert):
            # Xref information
            alert_obj.additional = alert[5]

        # alert object created, now validate and add to new list
        if alert_obj.validate():
            alerts_validated.append(alert_obj)
        else:
            alerts_corrupted.append(alert_obj)

    print('[*] Importing alerts successful (' + str(len(alerts_validated)) + ' successful / ' + str(
        len(alerts_corrupted)) + ' ignored)')
    return alerts_validated


def calculate_time_ranges(imported, intv=5):
    """
    calculates intv time ranges (steps)
    :param imported: validated alerts (list of alert objects)
    :return: list with timestamps
    """
    start = datetime.datetime.strptime(imported[0].timestamp, "%Y/%m/%d-%H:%M:%S.%f")
    end = datetime.datetime.strptime(imported[len(imported) - 1].timestamp, "%Y/%m/%d-%H:%M:%S.%f")
    diff = (end - start) / intv
    result = []
    for i in range(intv - 1):
        result.append((start + diff * i))  # .strftime("%Y/%m/%d-%H:%M:%S.%f"))
    result.append(end)  # .strftime("%Y/%m/%d-%H:%M:%S.%f")

    return result


def generate_nodes_and_edges(alerts_validated, time_ranges=None):
    """
    generates nodes and edges from the alert objects and returns one or a list of nodes and edges
    :param alerts_validated: list of alert objects
    :param time_ranges: if existing: time ranges/steps to which the nodes and edges need to be divided
    :return: a list of nodes and a list of edges (no time ranges) OR a list of dicts of nodes and a list of dicts of edges (according to the time ranges)
    """
    print('[*] Start generating nodes and edges')
    all_nodes = []
    all_edges = []
    nodes_list = []
    edges_list = []
    i = 0

    for alert_obj in alerts_validated:
        if time_ranges:
            current_alert_time = datetime.datetime.strptime(alert_obj.timestamp, "%Y/%m/%d-%H:%M:%S.%f")

            if current_alert_time > time_ranges[i]:
                # current alert exceeds the current time range
                # copy/save all nodes & edges until now
                cur_nodes_dict = pd.DataFrame.from_records(node.to_dict() for node in copy.deepcopy(all_nodes))
                cur_edges_dict = pd.DataFrame.from_records(edge.to_dict() for edge in copy.deepcopy(all_edges))
                nodes_list.append(cur_nodes_dict)
                edges_list.append(cur_edges_dict)
                i = i + 1

                # move current alert to the right time range
                # check if the alert also exceeds the next time range and jump if necessary
                for x in range(i, len(time_ranges) - 1):
                    if current_alert_time > time_ranges[i]:
                        # current alert exceeds the current time range
                        # copy/save all nodes & edges until now
                        cur_nodes_dict = pd.DataFrame.from_records(node.to_dict() for node in copy.deepcopy(all_nodes))
                        cur_edges_dict = pd.DataFrame.from_records(edge.to_dict() for edge in copy.deepcopy(all_edges))
                        nodes_list.append(cur_nodes_dict)
                        edges_list.append(cur_edges_dict)
                        i = i + 1

        # NODE
        # check if node already exists and update type
        # check From IP
        existing_node, index = find_node_by_ip(all_nodes, alert_obj.from_ip)
        if existing_node:
            if existing_node.get_type() == TYPE_VICTIM:
                existing_node.set_type(TYPE_COMPROMISED)
            if alert_obj.from_port:
                existing_node.add_port_out(alert_obj.from_port)
            all_nodes[index] = existing_node
        else:
            # create new node
            new_node = Node(alert_obj.from_ip, TYPE_ATTACKER)
            if alert_obj.from_port:
                new_node.add_port_out(alert_obj.from_port)
            all_nodes.append(new_node)

        # check To IP
        existing_node, index = find_node_by_ip(all_nodes, alert_obj.to_ip)
        if existing_node:
            if alert_obj.to_port:
                existing_node.add_port_in(alert_obj.to_port)
            all_nodes[index] = existing_node
        else:
            # create new node
            new_node = Node(alert_obj.to_ip, TYPE_VICTIM)
            if alert_obj.to_port:
                new_node.add_port_in(alert_obj.to_port)
            all_nodes.append(new_node)

        # EDGE
        # check if edge already exists
        flag = False
        for index, edge in enumerate(all_edges):
            # compare with each edge and check if there exists already the same type
            if edge.compare_with_alert(alert_obj):
                edge.merge_with_alert(alert_obj)
                all_edges[index] = edge
                flag = True

        if not flag:
            new_edge = Edge([alert_obj.name], [alert_obj.classification], [alert_obj.priority], alert_obj.from_ip,
                            alert_obj.to_ip, [0], [alert_obj.from_port], [alert_obj.to_port], [alert_obj.timestamp],
                            [alert_obj.additional])
            all_edges.append(new_edge)

    cur_nodes_dict = pd.DataFrame.from_records(node.to_dict() for node in copy.deepcopy(all_nodes))
    cur_edges_dict = pd.DataFrame.from_records(edge.to_dict() for edge in copy.deepcopy(all_edges))

    nodes_list.append(cur_nodes_dict)
    edges_list.append(cur_edges_dict)

    print('[*] Nodes and Edges successfully generated')
    if time_ranges:
        return nodes_list, edges_list
    else:
        return all_nodes, all_edges


def export_to_csv(nodes, edges):
    """
    generates a csv file and saves under fix name
    :param nodes: list of nodes
    :param edges: list of edges
    :return: nothing
    """
    print('[*] Start exporting to csv (nodes.csv, edges.csv in root folder)')

    df_n = pd.DataFrame.from_records(node.to_dict() for node in nodes)
    df_n.to_csv('nodes.csv', index=False)

    df_e = pd.DataFrame.from_records(edge.to_dict() for edge in edges)
    df_e.to_csv('edges.csv', index=False)

    print('[*] csv successfully exported')
    return 'nodes.csv', 'edges.csv'


def scale_in_range(x, min_before, max_before, min_after=1, max_after=10):
    """converts values in the range [min_before,max_before] to values in the range [min_after,max_after]"""
    return float(min_after + float(x - min_before) * float(max_after - min_after) / (max_before - min_before))


def find_node_by_ip(all_nodes, ip):
    """finds an existing node in all_nodes by given IP"""
    for index, node in enumerate(all_nodes):
        if node.ip == ip:
            return node, index
    return None, None


def find_min_max_number_of_alerts(edges):
    """return the minimal and maximal number of alerts connected to an edge"""
    min_value = None
    max_value = None
    for edge in edges:
        value = edge.number_alerts
        if not min_value:
            min_value = value
        if not max_value:
            max_value = value
        if value < min_value:
            min_value = value
        if value > max_value:
            max_value = value

    return min_value, max_value


class Node:
    # parameterized constructor
    def __init__(self, ip_address, type):
        self.ip = ip_address
        self.type = type  # 1: Attacker, 2: Victim, 3: Compromised
        self.ports_in = []
        self.ports_out = []

    def add_port_in(self, port):
        if port not in self.ports_in:
            self.ports_in.append(port)

    def add_port_out(self, port):
        if port not in self.ports_out:
            self.ports_out.append(port)

    def get_type(self):
        return self.type

    def set_type(self, new_type):
        self.type = new_type

    def to_dict(self):
        return {
            'IP': self.ip,
            'Type': self.type,
            'Ports in': self.ports_in,
            'Ports out': self.ports_out,
        }


class Edge:
    # parameterized constructor
    def __init__(self, attack_names, classifications, priorities, from_ip, to_ip, directions, from_ports, to_ports, timestamps,
                 additional):
        self.attack_names = attack_names
        self.classifications = classifications
        self.priorities = priorities
        self.from_ip = from_ip
        self.to_ip = to_ip
        self.directions = directions
        self.number_alerts = [1]  # number of alerts per attack

        self.from_ports = []
        if from_ports:
            self.from_ports.append(from_ports)
        self.to_ports = []
        if to_ports:
            self.to_ports.append(to_ports)
        self.timestamps = []
        self.timestamps.append(timestamps)
        self.additional = []
        if additional:
            self.additional.append(additional)
        self.weight = 1  # sum of all alerts related to this edge

    def update_weight(self, min_number_alerts, max_number_alerts):
        """update the weight (width of the edge) corresponding to the number of alerts and scale limit"""
        self.weight = scale_in_range(self.number_alerts, min_number_alerts, max_number_alerts,
                                     EDGE_WEIGHT_SCALING_MIN, EDGE_WEIGHT_SCALING_MAX)

    def compare_with_alert(self, alert):
        """compare edge with alert and return true if can be merged"""
        if (self.from_ip == alert.from_ip and self.to_ip == alert.to_ip) or (
                self.from_ip == alert.to_ip and self.to_ip == alert.from_ip):
            return True
        else:
            return False

    def merge_with_alert(self, alert):
        """add alert information to existing edge"""
        # check if attack exists already in this edge
        index = self.find_attack_in_edge(alert)
        if isinstance(index, int):
            # add alert to attack
            self.merge_alert_with_attack(index, alert)
        else:
            # create new attack
            self.add_new_attack_to_edge(alert)

    def find_attack_in_edge(self, alert):
        """find existing attack in current edge and return index (consider also direction!)"""
        if alert.from_ip == self.from_ip:
            direction = 0
        else:
            direction = 1
        for index, attack_name in enumerate(self.attack_names):
            if attack_name == alert.name:
                if self.directions[index] == direction:
                    return index
        return None

    def merge_alert_with_attack(self, index, alert):
        """add all alert information to the corresponding attack in the edge (at index)"""
        if alert.from_port not in self.from_ports[index]:
            self.from_ports[index].append(alert.from_port)
        if alert.to_port not in self.to_ports[index]:
            self.to_ports[index].append(alert.to_port)
        if alert.additional not in self.additional[index]:
            self.additional[index].append(alert.additional)
        if alert.timestamp not in self.timestamps[index]:
            self.timestamps[index].append(alert.timestamp)
        self.number_alerts[index] += 1  # increase number of this alert
        self.weight += 1  # increase sum of alerts related to the current edge

    def add_new_attack_to_edge(self, alert):
        if alert.from_ip == self.from_ip:
            direction = 0
        else:
            direction = 1
        """add new attack in edge (new index)"""
        self.attack_names.append(alert.name)
        self.classifications.append(alert.classification)
        self.priorities.append(alert.priority)
        self.directions.append(direction)
        self.from_ports.append([alert.from_port])
        self.to_ports.append([alert.to_port])
        self.timestamps.append([alert.timestamp])
        self.additional.append([alert.additional])
        self.number_alerts.append(1)
        self.weight += 1

    def to_dict(self):
        # shorten list of timestamps (to big for csv)
        # for index, timestamps in enumerate(self.timestamps):
        #     if len(timestamps) > 10:
        #         # take the first 10 timestamps -> ToDo ?!
        #         self.timestamps[index] = timestamps[:10]

        # Update: just take first and last timestamp
        for index, timestamps in enumerate(self.timestamps):
            self.timestamps[index] = str(timestamps[0]) + " --- " + str(timestamps[-1])
        return {
            'Attack Name': self.attack_names,
            'Classification': self.classifications,
            'Priority': self.priorities,
            'From IP': self.from_ip,
            'To IP': self.to_ip,
            'Attack Direction': self.directions,
            'From Ports': self.from_ports,
            'To Ports': self.to_ports,
            'Timestamps': self.timestamps,
            'Count': self.number_alerts,
            'Weight': self.weight,
            'Additional': self.additional,
        }
