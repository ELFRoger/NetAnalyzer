import sys
sys.path.append('../')
import json
import libs.common
import libs.db
import libs.logger

def update_originalData(http_list):
    db_cursor = libs.common.get_value('db_cursor')
    db_conn = libs.common.get_value('db_conn')

    data_count = len(http_list)
    count = 0
    success = 0
    param = []
    for http_data in http_list:
        '''
        sql_statement = ('INSERT INTO http_raw_data'
                        '(`time`, `src`, `dst`, `src_port`, `dst_port`, `http_type`, `method`, `url`, '
                        '`http_version`, `status`, `reason`, `headers`, `body` )'
                        'SELECT %s AS f1, %s AS f2, %s AS f3, %s AS f4, %s AS f5, %s AS f6, %s AS f7, '
                        '%s AS f8, %s AS f9, %s AS f10, %s AS f11, %s AS f12, %s AS f13 '
                        'WHERE NOT EXISTS'
                        '(SELECT * FROM http_raw_data WHERE time=%s AND src=%s AND dst=%s LIMIT 1)')
        '''
        sql_statement = ('INSERT INTO http_raw_data'
                        '(`time`, `src`, `dst`, `src_port`, `dst_port`, `http_type`, `method`, `url`, '
                        '`http_version`, `status`, `reason`, `headers`, `body` )'
                        'VALUE (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)')
        time = http_data['time']
        src = http_data['src']
        dst = http_data['dst']
        src_port = http_data['src_port']
        dst_port = http_data['dst_port']
        http_type = http_data['type']
        method = http_data['method']
        url = http_data['uri']
        http_version = http_data['http_version']
        status = http_data['status']
        reason = http_data['reason']
        headers = json.dumps(http_data['headers'])
        body = http_data['body']
        tmp_data = body.decode('UTF-8', 'ignore')
        if ('gbk' in tmp_data) or ('GBK' in tmp_data):
            body = body.decode('GBK', 'ignore')
        else:
            body = tmp_data

        param.append((
            time, src, dst, src_port, dst_port, http_type, method, url, http_version, status, reason, headers, body,
        ))
        count += 1
        success += 1
        # every 1000 data commit once
        if count == 1000 or data_count == success:
            db_cursor.executemany(sql_statement, param)
            db_conn.commit()
            count = 0
            param = []
            libs.logger.log('[%s / %s] insert db successfully' %(success, data_count))
    return


def request_filter():
    db_cursor = libs.common.get_value('db_cursor')
    db_conn = libs.common.get_value('db_conn')

    sql_statement = ('insert into http_request (time,src,src_port,method,url,http_version,headers) '
                     'select time,src,src_port,method,url,http_version,headers '
                     'from http_raw_data where http_type="request"')
    db_cursor.execute(sql_statement)
    db_conn.commit()
    return


def response_filter():
    db_cursor = libs.common.get_value('db_cursor')
    db_conn = libs.common.get_value('db_conn')

    sql_statement = ('insert into '
                     'http_response(time, src, src_port, http_version, status, reason, headers)'
                     'select time, src, src_port, http_version, status, reason, headers'
                     'from http_raw_data where http_type = "response"')
    db_cursor.execute(sql_statement)
    db_conn.commit()
    return


def select_all_UA():

    db_cursor = libs.common.get_value('db_cursor')
    db_conn = libs.common.get_value('db_conn')

    sql_statement = ("select src, headers from http_request where headers!='{}' limit 100000")

    db_cursor.execute(sql_statement)
    db_conn.commit()
    res = db_cursor.fetchall()
    UA_list = []
    for item in res:
        header = json.loads(item[1])
        if 'user-agent' in header.keys():
            temp = {}
            temp['ip'] = item[0]
            temp['UA'] = header['user-agent']
            UA_list.append(temp)
        else:
            continue

    return UA_list


def select_all_response_header():
    db_cursor = libs.common.get_value('db_cursor')
    db_conn = libs.common.get_value('db_conn')

    sql_statement = ("select src, headers from http_response where headers!='{}'")

    db_cursor.execute(sql_statement)
    db_conn.commit()
    res = db_cursor.fetchall()
    header_list = []
    for item in res:
        header = json.loads(item[1])
        if 'date' in header.keys():
            header.pop('date')
        temp = {}
        temp['ip'] = item[0]
        temp['header'] = str(header).replace('\'','').replace('{','').replace('}','')
        if temp['header']:
            header_list.append(temp)
        else:
            print(item)

    return header_list


def select_all_response_info():
    db_cursor = libs.common.get_value('db_cursor')
    db_conn = libs.common.get_value('db_conn')

    sql_statement = ("select src, src_port, http_version, reason, headers, status from http_response")

    db_cursor.execute(sql_statement)
    db_conn.commit()
    res = db_cursor.fetchall()

    return res


if __name__ == '__main__':
    libs.common._init()
    libs.db.db_cursor_init()

    print(select_all_response_header())
