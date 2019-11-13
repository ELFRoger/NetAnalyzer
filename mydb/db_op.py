import sys
sys.path.append('../')
import json
import libs.common
import libs.db
import libs.logger

def _init():
    libs.common._init()
    libs.db.db_cursor_init()


def update_originalData(http_list):
    _init()
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


def update_fingerprintData(fingerprint_list):
    _init()
    db_cursor = libs.common.get_value('db_cursor')
    db_conn = libs.common.get_value('db_conn')

    data_count = len(fingerprint_list)
    count = 0
    success = 0
    param = []
    for fingerprint in fingerprint_list:
        '''
        sql_statement = ('INSERT INTO http_raw_data'
                        '(`time`, `src`, `dst`, `src_port`, `dst_port`, `http_type`, `method`, `url`, '
                        '`http_version`, `status`, `reason`, `headers`, `body` )'
                        'SELECT %s AS f1, %s AS f2, %s AS f3, %s AS f4, %s AS f5, %s AS f6, %s AS f7, '
                        '%s AS f8, %s AS f9, %s AS f10, %s AS f11, %s AS f12, %s AS f13 '
                        'WHERE NOT EXISTS'
                        '(SELECT * FROM http_raw_data WHERE time=%s AND src=%s AND dst=%s LIMIT 1)')
        '''
        sql_statement = ('INSERT INTO tcpip_fingerprint'
                        '(`time`, `src`, `src_port`,`syn_len`, `win`, `ttl`, `df`, `rst`, `mss` )'
                        'VALUE (%s, %s, %s, %s, %s, %s, %s, %s, %s)')

        count += 1
        success += 1
        param.append([str(info) for info in fingerprint])
        # every 1000 data commit once
        if count == 1000 or data_count == success:
            print(param)
            db_cursor.executemany(sql_statement, param)
            db_conn.commit()
            count = 0
            param = []
            libs.logger.log('[%s / %s] insert db successfully' %(success, data_count))
    return


def request_filter():
    _init()
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


def select_all_UA(num):
    _init()
    db_cursor = libs.common.get_value('db_cursor')
    db_conn = libs.common.get_value('db_conn')

    if num:
        sql_statement = ("select src, headers from http_request where headers!='{}' limit %s"%num)
    else:
        sql_statement = ("select src, headers from http_request where headers!='{}' ")

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
    _init()
    db_cursor = libs.common.get_value('db_cursor')
    db_conn = libs.common.get_value('db_conn')

    sql_statement = ("select src, headers from http_response where headers!='{}'")

    db_cursor.execute(sql_statement)
    db_conn.commit()
    res = db_cursor.fetchall()

    counter = 0
    header_list = []
    for item in res:
        header = json.loads(item[1])
        #if 'date' in header.keys():
        #    header.pop('date')
        temp = {}
        feature = ''
        if 'server' in header.keys():
            if type(header['server']) == list:
                #print(header['server'])
                header['server'] = str(header['server'])
            feature += 'server:' + header['server']
        if 'www-authenticate' in header.keys():
            if type(header['www-authenticate']) == list:
                #print(header['www-authenticate'])
                header['www-authenticate'] = str(header['www-authenticate'])
            feature += 'www-authenticate:' + header['www-authenticate']
        if 'x-powered-by' in header.keys():
            if type(header['x-powered-by']) == list:
                #print(header['x-powered-by'])
                header['x-powered-by'] = str(header['x-powered-by'])
            feature += 'x-powered-by:' + header['x-powered-by']
        temp['ip'] = item[0]
        temp['header'] = feature
        if temp['header']:
            header_list.append(temp)
            counter += 1
        else:
            print(item)
    libs.logger.log('all item : %d' % (len(res)))
    libs.logger.log('filte item : %d' % (counter))
    return header_list


def select_all_response_info():
    _init()
    db_cursor = libs.common.get_value('db_cursor')
    db_conn = libs.common.get_value('db_conn')

    sql_statement = ("select src, src_port, http_version, reason, status, headers from http_response")

    db_cursor.execute(sql_statement)
    db_conn.commit()
    res = db_cursor.fetchall()

    return res


if __name__ == '__main__':
    libs.common._init()
    libs.db.db_cursor_init()

    print(select_all_response_header())
