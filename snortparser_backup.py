import json
import re
import pandas as pd
import datetime
import time

current_min_number_alerts = 0  # minimal number of an alert
current_max_number_alerts = 0  # maximal number of an alert
EDGE_WEIGHT_SCALING_MIN = 1 # scaled width of the edges
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

    from_port = None
    to_port = None
    additional = None

    def validate(self):
        if self.name and self.classification and self.priority and self.from_ip and self.to_ip and self.timestamp:
            #print(self.name + '...' + self.classification + '...' + self.priority)
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

    # with open(file_path, 'r') as current:
    #     lines = current.readlines()
    #     if not lines:
    #         print('FILE IS EMPTY')
    #         return -1
    #     else:
    #         # load alerts one by one
    #         alert = []  # new alert
    #         for line in lines:
    #             if line == '\n':
    #                 # alerts are separated by blank lines
    #                 all_alerts.append(alert)
    #                 alert = []
    #             else:
    #                 # add line to alert entry
    #                 alert.append(line.strip('\n'))
    # print('[*] Log file successfully read')
    # return all_alerts

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
    :param all_alerts:
    :return:
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

    print('[*] Importing alerts successful (' + str(len(alerts_validated)) + ' successful / ' + str(len(alerts_corrupted)) + ' ignored)')
    return alerts_validated


def calculate_time_ranges(imported, intv=10):
    """
    calculates 10 time ranges (steps)
    :param imported: validated alerts
    :return: 10 timestamps in a list
    """
    # timestamps of imported alerts are in format: %Y/%m/%d-%H:%M:%S.%f
    #print("Min Timestamp: " + str(min_timestamp) + " (" + imported[0].timestamp + ")")
    #print("Max Timestamp: " + str(max_timestamp) + " (" + imported[len(imported)-1].timestamp + ")")
    start = datetime.datetime.strptime(imported[0].timestamp, "%Y/%m/%d-%H:%M:%S.%f")
    end = datetime.datetime.strptime(imported[len(imported)-1].timestamp, "%Y/%m/%d-%H:%M:%S.%f")
    diff = (end - start) / intv
    result =[]
    for i in range(intv):
        result.append((start + diff * i))#.strftime("%Y/%m/%d-%H:%M:%S.%f"))
    result.append(end)#.strftime("%Y/%m/%d-%H:%M:%S.%f")
    print('Ranges: ' + str(result))
    return result


def generate_nodes_and_edges(alerts_validated, time_ranges=None):
    print('[*] Start generating nodes and edges')
    all_nodes = []
    all_edges = []
    nodes_list = []
    edges_list = []
    i = 0


    for alert_obj in alerts_validated:
        #datetime_object = datetime.datetime.strptime(str(datetime.datetime.now().year) + '/' + alert_obj.timestamp, '%Y/%m/%d-%H:%M:%S.%f')
        # For Later to get string back: print(datetime_object.strftime('%Y-%m-%d %H:%M:%S'))

        if time_ranges:
            max_i = len(time_ranges) - 1
            t1 = datetime.datetime.strptime(alert_obj.timestamp, "%Y/%m/%d-%H:%M:%S.%f")
            #t2 = datetime.datetime.strptime(time_ranges[len(nodes_list)+1], "%Y/%m/%d-%H:%M:%S.%f")
            #t2 = time_ranges[len(nodes_list)+1]
            t2 = time_ranges[i]

            if t1 > t2:
                #print('JETZZ:; ' + str(len(all_nodes)))
                # next step
                # all until now copy
                #nodes_list[len(nodes_list)-1] = all_nodes
                #nodes_list = nodes_list + all_nodes

                #curNodesDict = (node.to_dict() for node in all_nodes)
                #print("BB: " + str(curNodesDict))
                #curEdgesDict = (edge.to_dict() for edge in all_edges)

                curNodesDict = pd.DataFrame.from_records(node.to_dict() for node in all_nodes)
                curEdgesDict = pd.DataFrame.from_records(edge.to_dict() for edge in all_edges)

                nodes_list.append(curNodesDict)
                edges_list.append(curEdgesDict)
                i = i + 1
                #print("Groesse: " + str(len(nodes_list)))
                #print("von 1: " + str(len(nodes_list[0])))
                # append does not work like expected

                for x in range(i, len(time_ranges)-1):
                    if t1 > time_ranges[i]:
                        curNodesDict = pd.DataFrame.from_records(node.to_dict() for node in all_nodes)
                        curEdgesDict = pd.DataFrame.from_records(edge.to_dict() for edge in all_edges)

                        nodes_list.append(curNodesDict)
                        edges_list.append(curEdgesDict)
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
            if existing_node.get_type() == TYPE_ATTACKER:
                existing_node.set_type(TYPE_COMPROMISED)
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
            new_edge = Edge(alert_obj.name, alert_obj.classification, alert_obj.priority, alert_obj.from_ip, alert_obj.to_ip, alert_obj.from_port, alert_obj.to_port, alert_obj.timestamp, alert_obj.additional)
            all_edges.append(new_edge)

    curNodesDict = pd.DataFrame.from_records(node.to_dict() for node in all_nodes)
    curEdgesDict = pd.DataFrame.from_records(edge.to_dict() for edge in all_edges)

    nodes_list.append(curNodesDict)
    edges_list.append(curEdgesDict)
    # update weight
    # calculate min and max number of alerts per edge
    #min_number_alerts, max_number_alerts = find_min_max_number_of_alerts(all_edges)
    #for index, edge in enumerate(all_edges):
        #edge.update_weight(min_number_alerts, max_number_alerts)
        #all_edges[index] = edge

    print('[*] Nodes and Edges successfully generated')
    if time_ranges:
        print("Hier")
#        print("von 3: " + str(len(nodes_list[2])))
        return nodes_list, edges_list
    else:
        return all_nodes, all_edges
    # export to csv
    #export_to_csv(all_nodes, all_edges)

    #edge = ['200', new_alert.from_ip, new_alert.to_ip, datetime_object.strftime('%d/%m/%Y'), new_alert.from_port]
    # edges_data = [dates, times, from_ip, from_port, to_ip, to_port]


def export_to_csv(nodes, edges):
    print('[*] Start exporting to csv')
    nodes_data = []
    edges_data = []

    #df_n = pd.DataFrame(nodes_data, columns=['Account', 'CustomerName', 'Type'])
    #test1 = (node.to_dict() for node in nodes)
    #test = {c.name: c.value for c in test1}
    #print("CC: " + str(test))
    df_n = pd.DataFrame.from_records(node.to_dict() for node in nodes)
    df_n.to_csv('nodes.csv', index=False)

    #df_e = pd.DataFrame(edges_data, columns=['TransactionAmt', 'Source', 'Target', 'Date', 'From Port'])
    df_e = pd.DataFrame.from_records(edge.to_dict() for edge in edges)
    df_e.to_csv('edges.csv', index=False)

    print('[*] csv successfully exported')


def scale_in_range(x, min_before, max_before, min_after=1, max_after=10):
    """converts values in the range [min_before,max_before] to values in the range [min_after,max_after]"""
    return float(min_after + float(x - min_before) * float(max_after - min_after) / (max_before - min_before))


def find_node_by_ip(all_nodes, ip):
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
        #print('Node created: ' + self.ip)

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
    def __init__(self, attack_name, classification, priority, from_ip, to_ip, from_port, to_port, timestamp, additional):
        self.attack_name = attack_name
        self.classification = classification
        self.priority = priority
        self.from_ip = from_ip
        self.to_ip = to_ip

        self.from_ports = []
        if from_port:
            self.from_ports.append(from_port)
        self.to_ports = []
        if to_port:
            self.to_ports.append(to_port)
        self.timestamps = []  # list of datetimes
        self.timestamps.append(timestamp)
        self.number_alerts = 1
        self.weight = 1
        self.additional = []  # list of strings
        if additional:
            self.additional.append(additional)


    def update_weight(self, min_number_alerts, max_number_alerts):
        """updates the weight (width of the edge) corresponding to the number of alerts and scale limit"""
        self.weight = scale_in_range(self.number_alerts, min_number_alerts, max_number_alerts,
                                       EDGE_WEIGHT_SCALING_MIN, EDGE_WEIGHT_SCALING_MAX)


    def compare_with_alert(self, alert):
        """compare edge with alert and return true if can be merged"""
        if self.attack_name == alert.name and self.from_ip == alert.from_ip and self.to_ip == alert.to_ip and self.classification == alert.classification and self.priority == alert.priority:
            return True
        else:
            return False

    def merge_with_alert(self, alert):
        """add information to existing edge"""
        if alert.from_port and alert.from_port not in self.from_ports:
            self.from_ports.append(alert.from_port)
        if alert.to_port and alert.to_port not in self.to_ports:
            self.to_ports.append(alert.to_port)
        if alert.additional and alert.additional not in self.additional:
            self.additional.append(alert.additional)
        self.timestamps.append(alert.timestamp)
        self.number_alerts += 1

    def to_dict(self):
        # timestamp string
        timestamp_str = ''
        if len(self.timestamps) == 1:
            timestamp_str = str(self.timestamps[0])
        else:
            timestamp_str = str(self.timestamps[0]) + ' ... ' + str(self.timestamps[-1])
        return {
            'Attack Name': self.attack_name,
            'Classification': self.classification,
            'Priority': self.priority,
            'From IP': self.from_ip,
            'To IP': self.to_ip,
            'From Ports': self.from_ports,
            'To Ports': self.to_ports,
            'Timestamps': timestamp_str,
            'Count': self.number_alerts,
            'Weight': self.weight,
            'Additional': self.additional,
        }



