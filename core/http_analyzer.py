# encoding=utf-8

import libs.common
import libs.logger
import libs.db
import os
from db_op import update_originalData
from dpkt_engine import dpkt_http

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


def http_analyzer_by_dpkt(pcapFoler):
    # get all file list
    file_list = _get_fileList(pcapFoler)
    for file in file_list:
        libs.logger.log(pcapFoler + '\\' + file + ' is storing into db.....')
        http_list = dpkt_http(pcapFoler + '\\' + file)
        update_originalData(http_list)
        libs.logger.log(pcapFoler + '\\' + file + 'finished')


if __name__ == '__main__':
    _init()
    http_analyzer_by_dpkt('G:\\traffic_data\\test')
