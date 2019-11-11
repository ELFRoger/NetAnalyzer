# encoding=utf-8

import libs.common
import libs.logger
import libs.db
import os
import csv
from mydb.db_op import update_originalData, update_fingerprintData
from traffic_analyze.dpkt_engine import dpkt_http, dpkt_tcpip_fingerprint

def _init():
    libs.common._init()
    libs.db.db_cursor_init()

def _get_fileList(dir):
    # 获取当前目录下所有文件
    file_list = []
    for root, dirs, files in os.walk(dir):
        for file in files:
            if not file.endswith('.pcap'):
                files.remove(file)
        file_list.append(files)

    return file_list[0]


def http_analyzer_by_dpkt(pcapFolder):
    _init()
    # get all file list
    file_list = _get_fileList(pcapFolder)
    i = 0
    for file in file_list:
        if i == 21:
            break
        libs.logger.log(pcapFolder + '\\' + file + ' is analyzing.....')
        http_list = dpkt_http(pcapFolder + '\\' + file)
        libs.logger.log(pcapFolder + '\\' + file + ' is storing into db.....')
        update_originalData(http_list)
        libs.logger.log(pcapFolder + '\\' + file + 'finished')
        i += 1


def tcp_ip_fingerprint_analyze_by_dpkt(pcapFolder):
    _init()
    # get all file list
    file_list = _get_fileList(pcapFolder)
    i = 0
    for file in file_list:
        if i == 21:
            break
        libs.logger.log(pcapFolder + '\\' + file + ' is analyzing.....')
        fingerprint_list = dpkt_tcpip_fingerprint(pcapFolder + '\\' + file)
        libs.logger.log(pcapFolder + '\\' + file + ' is storing into db.....')
        update_fingerprintData(fingerprint_list)
        libs.logger.log(pcapFolder + '\\' + file + 'finished')
        i += 1


def tcp_ip_fingerprint_into_csv(pcapFolder):
    _init()
    # get all file list
    file_list = _get_fileList(pcapFolder)
    csvFile = open("fingerprint.csv", "w", newline='')  # 创建csv文件
    writer = csv.writer(csvFile, dialect='excel')  # 创建写的对象
    # 先写入columns_name
    first_row = ['timestamp', 'ip', 'sport', 'syn_len', 'win', 'ttl', 'df', 'rst', 'mss']
    writer.writerow(first_row)  # 写入列的名称
    i = 0
    for file in file_list:
        if i == 11:
            break
        libs.logger.log(pcapFolder + '\\' + file + ' is analyzing.....')
        fingerprint_list = dpkt_tcpip_fingerprint(pcapFolder + '\\' + file)
        libs.logger.log(pcapFolder + '\\' + file + ' is storing into csv.....')
        writer.writerows(fingerprint_list)
        libs.logger.log(pcapFolder + '\\' + file + 'finished')
        i += 1
    csvFile.close()


if __name__ == '__main__':
    _init()
    tcp_ip_fingerprint_into_csv('G:\\traffic_data\\divide')
