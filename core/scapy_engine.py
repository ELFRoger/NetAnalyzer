# encoding=utf-8
import scapy.all as scapy
import collections
import libs.common
import libs.logger
import libs.db
import os

try:
    # This import works from the project directory
    import scapy_http.http as http
except ImportError:
    # If you installed this package via pip, you just need to execute this
    from scapy.layers import http

def _http_filter(pcap):
    http_info = {'time', 'src', 'dst', 'src_port', 'dst_port', 'method', 'path', 'http_version', 'status_line',
                 'headers', 'additional_headers', 'raw'}
    http_data = collections.OrderedDict()

    http_data['time'] = pcap.time
    http_data['src'] = pcap.getlayer('IP').src
    http_data['dst'] = pcap.getlayer('IP').dst
    http_data['src_port'] = pcap.getlayer('TCP').sport
    http_data['dst_port'] = pcap.getlayer('TCP').dport
    if pcap.haslayer(http.HTTPRequest):
        http_data['method'] = pcap.getlayer(http.HTTPRequest).Method
        http_data['path'] = pcap.getlayer(http.HTTPRequest).Path
        http_data['http_version'] = pcap.getlayer(http.HTTPRequest).Http_Version
        http_data['status_line'] = 'none'
        http_data['headers'] = pcap.getlayer(http.HTTPRequest).Headers
        http_data['additional_headers'] = pcap.getlayer(http.HTTPRequest).Additional_Headers
    elif pcap.haslayer(http.HTTPResponse):
        http_data['method'] = 'none'
        http_data['path'] = 'none'
        http_data['http_version'] = 'none'
        http_data['status_line'] = pcap.getlayer(http.HTTPResponse).Status_Line
        http_data['headers'] = pcap.getlayer(http.HTTPResponse).Headers
        http_data['additional_headers'] = pcap.getlayer(http.HTTPResponse).Additional_Headers
    else:
        return 'none'
    if pcap.haslayer('Raw'):
        raw_data = pcap.getlayer('Raw').load
        # 解决编码问题
        '''
        tmp_data = raw_data.decode('UTF-8', 'ignore')
        if ('gbk' in tmp_data) or ('GBK' in tmp_data):
            data = raw_data.decode('GBK', 'ignore')
        else:
            data = tmp_data
        http_data['raw'] = data
        '''
        http_data['raw'] = raw_data
    else:
        http_data['raw'] = 'none'
    return http_data


def _http_analyze(pcapfile):
    pcaps = scapy.rdpcap(pcapfile)
    http_list = list()
    for pcap in pcaps:
        if pcap.haslayer('HTTP'):
            http_data = _http_filter(pcap)
            if http_data == 'none':
                continue
            else:
                http_list.append(http_data)
    return http_list

def _get_fileList(dir):
    # 获取当前目录下所有文件
    file_list = []
    for root, dirs, files in os.walk(dir):
        file_list.append(files)
    return file_list[0]


def scapy_http(filename):
    return _http_analyze(filename)


if __name__ == '__main__':
    http_list = _http_analyze('')
    print(http_list)
    print(len(http_list))
    libs.common._init()
    libs.db.db_cursor_init()
    # http_analyzer('G:\\traffic_data\\test')