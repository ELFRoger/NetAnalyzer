#!/usr/bin/env python
# -*- coding: utf-8 -*-
from db_op import select_all_response_info
import csv
import config
import json
from libs import common
from libs import db
from libs import logger


def _init():
    common._init()
    db.db_cursor_init()


def save_response_feature_to_csv():
    response_info = select_all_response_info()
    response_keys = config.respose_header_key
    first_row = ['src', 'src_port', 'http_version', 'reason', 'status',]
    first_row.extend(response_keys)
    first_row.append('headers')

    csvFile = open("responseData.csv", "w", newline='')  # 创建csv文件
    writer = csv.writer(csvFile, dialect='excel')  # 创建写的对象
    # 先写入columns_name
    writer.writerow(first_row)  # 写入列的名称
    # 写入多行用writerows                                #写入多行

    for item in response_info:
        write_info = []

        write_info.append(item[4])
        header = item[5]
        for key in response_keys:
            if key in header:
                if key == 'content-length':
                    temp = json.loads(header)
                    try:
                        if isinstance(temp[key], list):
                            write_info.append(int(temp[key][0]))
                        elif temp[key]:
                            write_info.append(int(temp[key]))
                        else:
                            write_info.append(1)
                    except:
                        write_info.append(1)
                else:
                    write_info.append(1)
            else:
                write_info.append(0)
        write_info.append(item[0])
        write_info.append(item[1])
        write_info.append(item[2])
        write_info.append(item[3])
        write_info.append(item[5])
        if write_info:
            writer.writerow(write_info)
        else:
            pass

    csvFile.close()



_init()
save_response_feature_to_csv()


