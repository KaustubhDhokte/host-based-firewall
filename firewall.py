"""
"""
import csv


def process_ip(ip):
    """

    :param ip:
    :return:
    """
    octets = ip.split('.')
    new_ip = str()
    for octet in octets:
        l = 3 - len(octet)
        if l:
            new_octet = str('0' * l) + octet
        else:
            new_octet = octet
        new_octet = new_octet + '.'
        new_ip = new_ip + new_octet
    new_ip = new_ip[:-1]
    return new_ip


class BSTree(object):
    """

    """
    def __init__(self, head=None):
        """

        """
        self.head = head
        self.current = head

    def insert(self, node):
        """

        :param node:
        :return:
        """
        if not self.head:
            self.head = node
        else:
            curr = self.head
            while True:
                if node.port < curr.port:
                    if curr.left:
                        curr = curr.left
                    else:
                        curr.left = node
                        break
                elif node.port > curr.port:
                    if curr.right:
                        curr = curr.right
                    else:
                        curr.right = node
                        break
                else:
                    curr.update(node)
                    break

    def search(self, port):
        """

        :param node:
        :return:
        """
        curr = self.head
        while True:
            if curr.port == port:
                return curr
            if not curr.left and not curr.right:
                return None
            elif port < curr.port:
                if curr.left:
                    curr = curr.left
                else:
                    return None
            elif port > curr.port:
                if curr.right:
                    curr = curr.right
                else:
                    return None


class Node(object):
    """

    """
    def __init__(self, port, traffic, protocol, ip):
        """

        """
        self.port = port
        self.traffic = []
        self.traffic.append(traffic)
        self.protocols = []
        self.protocols.append(protocol)
        self.ip = {'addresses':[],
                   'ranges': []
                   }
        if '-' in ip:
            parts = ip.split('-')
            start = process_ip(parts[0])
            end = process_ip(parts[1])
            self.ip['ranges'].append({'start': start, 'end': end})
        else:
            self.ip['addresses'].append(process_ip(ip))
        self.left = None
        self.right = None

    def update(self, node):
        """

        :return:
        """
        self.update_ip(node.ip)
        self.update_protocol(node.protocols)
        self.update_traffic(node.traffic)

    def update_traffic(self, traffic):
        """

        :param traffic:
        :return:
        """
        if traffic not in self.traffic:
            self.traffic.append(traffic)

    def update_protocol(self, protocol):
        """

        :param traffic:
        :return:
        """
        if protocol not in self.protocols:
            self.protocols.append(protocol)

    def update_ip(self, ip):
        """

        :param ip:
        :return:
        """
        if len(ip['ranges']) > 0:
            for range1 in ip['ranges']:
                start = range1['start']
                end = range1['end']
                for range in self.ip['ranges']:
                    if start < range['start']:
                        if end < range['start']:
                            self.ip['ranges'].append({'start': start, 'end': end})
                        else:
                            if end > range['end']:
                                range['end'] = end
                    else:
                        if start > range['end']:
                            self.ip['ranges'].append({'start': start, 'end': end})
                        else:
                            if end > range['end']:
                                range['end'] = end
        if len(ip['addresses']) > 0:
            in_range = False
            for range in self.ip['ranges']:
                if ip == max(range['start'], ip):
                    if ip == min(ip, range['end']):
                        in_range = True
                        break
            if not in_range:
                self.ip['addresses'].append(ip)


class Firewall(object):
    """
    Firewall
    """
    def __init__(self, path_to_csv):
        """

        :param path_to_csv:
        """

        with open(path_to_csv) as csvfile:
            reader = csv.reader(csvfile)
            t = BSTree()
            for row in reader:
                traffic = row[0]
                protocol = row[1]
                ip = row[3]
                ports = row[2]
                if '-' in ports:
                    nports = ports.split('-')
                    port1 = int(nports[0])
                    portn = int(nports[1])
                    for p in range(port1, portn):
                        n = Node(p, traffic, protocol, ip)
                        t.insert(n)
                else:
                    n = Node(int(ports), traffic, protocol, ip)
                    t.insert(n)
        self.tree = t

    def accept_packet(self, direction, protocol, port, ip_address):
        """

        :param direction:
        :param protocol:
        :param port:
        :param ip_address:
        :return:
        """
        ip_address = process_ip(ip_address)
        n = self.tree.search(int(port))
        if not n:
            return False
        else:
            if direction in n.traffic:
                if protocol in n.protocols:
                    if ip_address in n.ip["addresses"]:
                        return True
                    else:
                        ranges = n.ip['ranges']
                        for range in ranges:
                            if ip_address > range['start'] and ip_address < range['end']:
                                return True
        return False

if __name__ == '__main__':
    fw = Firewall('input.txt')
    print(fw.accept_packet("inbound", "tcp", 80, "192.168.1.2"))
    print(fw.accept_packet("inbound", "udp", 53, "192.168.2.1"))
    print(fw.accept_packet("outbound", "tcp", 10234, "192.168.10.11"))
    print(fw.accept_packet("inbound", "tcp", 81, "192.168.1.2"))
    print(fw.accept_packet("inbound", "udp", 24, "52.12.48.92"))
    print(fw.accept_packet("inbound", "tcp", 53, "192.168.2.1"))
