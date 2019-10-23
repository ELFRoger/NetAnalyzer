import dpkt
import datetime
import socket
import collections
from dpkt.compat import compat_ord


def mac_addr(address):
    """Convert a MAC address to a readable/printable string
       Args:
           address (str): a MAC address in hex form (e.g. '\x01\x02\x03\x04\x05\x06')
       Returns:
           str: Printable/readable MAC address
    """
    return ':'.join('%02x' % compat_ord(b) for b in address)


def inet_to_str(inet):
    """Convert inet object to a string
        Args:
            inet (inet struct): inet network address
        Returns:
            str: Printable/readable IP address
    """
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)


def _http_filter(filename):
    f = open(filename, 'rb')
    pcap = dpkt.pcap.Reader(f)

    http_list = []
    # For each packet in the pcap process the contents
    for timestamp, buf in pcap:
        http_data = collections.OrderedDict()
        eth = dpkt.ethernet.Ethernet(buf)  # Unpack the Ethernet frame (mac src/dst, ethertype)

        if not isinstance(eth.data, dpkt.ip.IP):  # Make sure the Ethernet data contains an IP packet
            print('Non IP Packet type not supported %s\n' % eth.data.__class__.__name__)
            continue

        ip = eth.data  # Now grab the data within the Ethernet frame (the IP packet)

        if isinstance(ip.data, dpkt.tcp.TCP):  # Check for TCP in the transport layer
            tcp = ip.data  # Set the TCP data

            # Now see if we can parse the contents as a HTTP request
            try:
                request = dpkt.http.Request(tcp.data)
            except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                request = ''
                pass

            try:
                response = dpkt.http.Response(tcp.data)
            except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                response = ''
                pass

            if not request and not response:
                continue

            # Pull out fragment information (flags and offset all packed into off field, so use bitmasks)
            receiver_window = tcp.win
            time_to_live = ip.ttl
            do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
            reset = tcp.flags
            more_fragments = bool(ip.off & dpkt.ip.IP_MF)
            fragment_offset = ip.off & dpkt.ip.IP_OFFMASK



            # record the info
            '''
            print('Timestamp: ', str(datetime.datetime.utcfromtimestamp(timestamp)))
            print('Ethernet Frame: ', mac_addr(eth.src), mac_addr(eth.dst), eth.type)
            print('IP: %s:%s -> %s:%s   (len=%d ttl=%d DF=%d MF=%d offset=%d)' % \
                (inet_to_str(ip.src), tcp.sport, inet_to_str(ip.dst), tcp.dport, ip.len, ip.ttl, do_not_fragment, more_fragments,
                fragment_offset))
            '''
            http_data['time'] = timestamp
            http_data['src'] = inet_to_str(ip.src)
            http_data['dst'] = inet_to_str(ip.dst)
            http_data['src_port'] = tcp.sport
            http_data['dst_port'] = tcp.dport
            if request:
                http_data['type'] = 'request'
                http_data['http_version'] = request.version
                http_data['method'] = request.method
                http_data['uri'] = request.uri
                http_data['status'] = 'none'
                http_data['reason'] = 'none'
                http_data['headers'] = request.headers
                http_data['body'] = request.body
            if response:
                http_data['type'] = 'response'
                http_data['http_version'] = response.version
                http_data['method'] = 'none'
                http_data['uri'] = 'none'
                http_data['status'] = response.status
                http_data['reason'] = response.reason
                http_data['headers'] = response.headers
                http_data['body'] = response.body

            http_list.append(http_data)
    return http_list

def _tcp_ip_fingerprint():
    return

def dpkt_http(filename):
    return _http_filter(filename)

if __name__ == '__main__':
    dpkt_http('')