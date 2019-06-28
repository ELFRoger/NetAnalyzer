import libs.common
import json

def update_originalData(http_list):
    db_cursor = libs.common.get_value('db_cursor')
    db_conn = libs.common.get_value('db_conn')

    data_count = len(http_list)
    count = 0
    success = 0
    for http_data in http_list:
        sql_statement = ('INSERT INTO http_raw_data'
                        '(`time`, `src`, `dst`, `src_port`, `dst_port`, `http_type`, `method`, `url`, '
                        '`http_version`, `status`, `reason`, `headers`, `body` )'
                        'SELECT %s AS f1, %s AS f2, %s AS f3, %s AS f4, %s AS f5, %s AS f6, %s AS f7, '
                        '%s AS f8, %s AS f9, %s AS f10, %s AS f11, %s AS f12, %s AS f13 '
                        'WHERE NOT EXISTS'
                        '(SELECT * FROM http_raw_data WHERE time=%s AND src=%s AND dst=%s LIMIT 1)')

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

        db_cursor.execute(sql_statement, (
            time, src, dst, src_port, dst_port, http_type, method, url, http_version, status, reason, headers, body,
            time, src, dst,
        ))
        count += 1
        # every 1000 data commit once
        if count == 100 or (data_count - success) / 100 - count == 0:
            db_conn.commit()
            success += count
            count = 0
            libs.logger.log('[%s / %s] insert db successfully' %(success, data_count))
    return

