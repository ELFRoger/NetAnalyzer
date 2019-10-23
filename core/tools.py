import db_op
import csv
import config
import json
import libs


def _init():
    libs.common._init()
    libs.db.db_cursor_init()


def save_response_feature_to_csv():
    response_info = db_op.select_all_response_info()
    response_keys = config.respose_header_key
    first_row = ['src', 'src_port', 'http_version', 'reason', 'headers', 'status',]
    first_row.extend(response_keys)

    csvFile = open("responseData.csv", "w")  # 创建csv文件
    writer = csv.writer(csvFile)  # 创建写的对象
    # 先写入columns_name
    writer.writerow(first_row)  # 写入列的名称
    # 写入多行用writerows                                #写入多行

    for item in response_info:
        write_info = []
        write_info.append(item[0])
        write_info.append(item[1])
        write_info.append(item[2])
        write_info.append(item[3])
        write_info.append(item[4])
        write_info.append(item[5])

        header = item[4]
        for key in response_keys:
            if key in header:
                if key == 'content-length':
                    temp = json.loads(header)
                    write_info.append(int(temp[key]))
                else:
                    write_info.append(1)
            else:
                write_info.append(0)

        writer.writerow(write_info)

    csvFile.close()


if __name__ == '__main__':
    _init()
    save_response_feature_to_csv()


