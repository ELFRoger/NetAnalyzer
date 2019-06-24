# encoding=utf-8
import scapy.all as scapy
try:
    # This import works from the project directory
    import scapy_http.http as http
except ImportError:
    # If you installed this package via pip, you just need to execute this
    from scapy.layers import http

import collections

def http_filter(pcap):
    http_info = {'time', 'src', 'dst', 'src_port', 'dst_port', 'method', 'path', 'http-version', 'status-line',
                 'headers', 'additional-headers', 'raw'}
    http_data = collections.OrderedDict()

    http_data['time'] = pcap.time
    http_data['src'] = pcap.getlayer('IP').src
    http_data['dst'] = pcap.getlayer('IP').dst
    http_data['src_port'] = pcap.getlayer('TCP').sport
    http_data['dst_port'] = pcap.getlayer('TCP').dport
    if pcap.haslayer(http.HTTPRequest):
        http_data['method'] = pcap.getlayer(http.HTTPRequest).Method
        http_data['path'] = pcap.getlayer(http.HTTPRequest).Path
        http_data['http-version'] = pcap.getlayer(http.HTTPRequest).Http_Version
        http_data['status-line'] = 'none'
        http_data['headers'] = pcap.getlayer(http.HTTPRequest).Headers
        http_data['additional-headers'] = pcap.getlayer(http.HTTPRequest).Additional_Headers
    elif pcap.haslayer(http.HTTPResponse):
        http_data['method'] = 'none'
        http_data['path'] = 'none'
        http_data['http-version'] = 'none'
        http_data['status-line'] = pcap.getlayer(http.HTTPResponse).Status_Line
        http_data['headers'] = pcap.getlayer(http.HTTPResponse).Headers
        http_data['additional-headers'] = pcap.getlayer(http.HTTPResponse).Additional_Headers
    else:
        return 'none'
    if pcap.haslayer('Raw'):
        raw_data = pcap.getlayer('Raw').load
        #解决编码问题
        tmp_data = raw_data.decode('UTF-8', 'ignore')
        if ('gbk' in tmp_data) or ('GBK' in tmp_data):
            data = raw_data.decode('GBK', 'ignore')
        else:
            data = tmp_data
        http_data['raw'] = data
        print(data)
    else:
        http_data['raw'] = 'none'
    return http_data


def http_analyze(pcapfile):
    pcaps = scapy.rdpcap(pcapfile)
    http_list = list()
    i = 0
    for pcap in pcaps:
        if pcap.haslayer('HTTP'):

            http_data = http_filter(pcap)
            if http_data == 'none':
                continue
            else:
                http_list.append(http_data)
    return http_list


http_list = http_analyze('http_00000_20190529155900.pcap')
print(http_list)
