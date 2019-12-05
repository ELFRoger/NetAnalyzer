import sys
sys.path.append('../')
import json
import libs.common
import libs.db
import libs.logger
import config

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
        sql_statement = ('INSERT INTO tcpip_syn_fingerprint'
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
            #print(item)
            pass
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


#获取聚类结果对应的特征
def get_ua_by_clusterNum(num, cluster_type):
    _init()
    db_cursor = libs.common.get_value('db_cursor')
    db_conn = libs.common.get_value('db_conn')

    if cluster_type == 'kmeans':
        sql_statement = ('select ua from ua_result where kmeans = %s' %num)
    elif cluster_type == 'cosion':
        sql_statement = ('select ua from ua_result where cosion = %s' % num)
    else:
        libs.logger.log('no such type cluster: %s' %cluster_type)
        return
    db_cursor.execute(sql_statement)
    db_conn.commit()
    res = db_cursor.fetchall()
    ua_dic = {}
    for item in res:
        if item[0] in ua_dic.keys():
            ua_dic[item[0]] += 1
        else:
            ua_dic[item[0]] = 1
    ua_dic_sorted = sorted(ua_dic.items(), key=lambda x: x[1],reverse=True)
    return ua_dic_sorted,len(res)


def get_resp_banner_by_clusterNum(num, cluster_type):
    _init()
    db_cursor = libs.common.get_value('db_cursor')
    db_conn = libs.common.get_value('db_conn')

    if cluster_type == 'kmeans':
        sql_statement = ('select banner from response_banner_result where kmeans = %s' %num)
    elif cluster_type == 'cosion':
        sql_statement = ('select banner from response_banner_result where cosion = %s' % num)
    else:
        libs.logger.log('no such type cluster: %s' %cluster_type)
        return
    db_cursor.execute(sql_statement)
    db_conn.commit()
    res = db_cursor.fetchall()
    banner_dic = {}
    for item in res:
        if item[0] in banner_dic.keys():
            banner_dic[item[0]] += 1
        else:
            banner_dic[item[0]] = 1
    resp_banner_dic_sorted = sorted(banner_dic.items(), key=lambda x: x[1],reverse=True)
    return resp_banner_dic_sorted,len(res)


def get_web_fingerprint_by_clusterNum(num, cluster_type):
    _init()
    db_cursor = libs.common.get_value('db_cursor')
    db_conn = libs.common.get_value('db_conn')

    if cluster_type == 'kmeans':
        sql_statement = ('select filter_headers from web_fingerprint_result_10w_3000 where kmeans = %s' %num)
    elif cluster_type == 'cosion':
        sql_statement = ('select filter_headers from web_fingerprint_result_10w_3000 where cosion = %s' % num)
    else:
        libs.logger.log('no such type cluster: %s' %cluster_type)
        return
    db_cursor.execute(sql_statement)
    db_conn.commit()
    res = db_cursor.fetchall()
    banner_dic = {}
    for item in res:
        if item[0] in banner_dic.keys():
            banner_dic[item[0]] += 1
        else:
            banner_dic[item[0]] = 1
    web_fingerprint_dic_sorted = sorted(banner_dic.items(), key=lambda x: x[1],reverse=True)
    return web_fingerprint_dic_sorted,len(res)


def get_tcpip_fingerprint_by_clusterNum(cluster_type):
    _init()
    db_cursor = libs.common.get_value('db_cursor')
    db_conn = libs.common.get_value('db_conn')

    if cluster_type == 'kmeans':
        sql_statement = ('select km_class,syn_len,win,ttl,df,rst,mss from tcpip_feature_number_max_all_km ')
    elif cluster_type == 'cosion':
        sql_statement = (
        'select cosion_km_class,syn_len,win,ttl,df,rst,mss from tcpip_feature_number_max_all_cosion_km ')
    else:
        libs.logger.log('no such type cluster: %s' %cluster_type)
        return
    db_cursor.execute(sql_statement)
    db_conn.commit()
    res = db_cursor.fetchall()
    fingerprint_list = [list(x) for x in res]


    return fingerprint_list


#tags_save_to_db
def save_tag(feature_type,cluster_type,tag_dict):
    _init()
    db_cursor = libs.common.get_value('db_cursor')
    db_conn = libs.common.get_value('db_conn')

    if feature_type in config.FEATRUE_TYPE:
        sql_statement = ('INSERT INTO cluster_result'
                         '(`cluster_type`, `cluster_num`, `cluster_tag`, `feature_type`) '
                         'VALUE (%s, %s, %s, %s)')
        param = []
        for clusterNum,tag in tag_dict.items():
            param.append((cluster_type, clusterNum, tag, feature_type))
        db_cursor.executemany(sql_statement, param)
        db_conn.commit()
        libs.logger.log('[%s / %s] insert db successfully' % (feature_type, cluster_type))

    else:
        libs.logger.log('[error] %s is not a feature type' % feature_type)
        return

    return


#获取tags
def get_all_cluster_tags(cluster_type = 'cosion'):
    _init()
    db_cursor = libs.common.get_value('db_cursor')
    db_conn = libs.common.get_value('db_conn')

    sql_statement = ('select feature_type,cluster_num,cluster_tag '
                     'from cluster_result '
                     'WHERE cluster_type = %s')

    db_cursor.execute(sql_statement, cluster_type)
    db_conn.commit()
    res = db_cursor.fetchall()
    tag_dict = {}
    tag_dict['ua_banner'] = {}
    tag_dict['response_banner'] = {}
    tag_dict['web_fingerprint'] = {}
    tag_dict['tcpip_fingerprint'] = {}
    for item in res:
        tag_dict[item[0]][item[1]] = item[2]


    sql_statement = ('select feature_type,cluster_num,cluster_tag '
                     'from cluster_result '
                     'WHERE cluster_type = %s and feature_type = %s')

    db_cursor.execute(sql_statement, ('kmeans', 'web_fingerprint'))
    db_conn.commit()
    res = db_cursor.fetchall()
    for item in res:
        tag_dict[item[0]][item[1]] = item[2]

    return tag_dict


def deal_web_fingerprint():
    _init()
    db_cursor = libs.common.get_value('db_cursor')
    db_conn = libs.common.get_value('db_conn')
    sql_statement = ('select src, headers, cosion, kmeans, id '
                     'from web_fingerprint_result_10w_3000 ')
    db_cursor.execute(sql_statement)
    db_conn.commit()
    res = db_cursor.fetchall()

    counter = 0

    param = []
    for item in res:
        header = json.loads(item[1])
        feature = ''
        if 'server' in header.keys():
            if type(header['server']) == list:
                # print(header['server'])
                header['server'] = str(header['server'])
            feature += 'server:' + header['server']
        if ' www-authenticate' in header.keys():
            if type(header['www-authenticate']) == list:
                # print(header['www-authenticate'])
                header['www-authenticate'] = str(header['www-authenticate'])
            feature += ' www-authenticate:' + header['www-authenticate']
        if 'x-powered-by' in header.keys():
            if type(header['x-powered-by']) == list:
                # print(header['x-powered-by'])
                header['x-powered-by'] = str(header['x-powered-by'])
            feature += ' x-powered-by:' + header['x-powered-by']
        if 'via' in header.keys():
            if type(header['via']) == list:
                # print(header['x-powered-by'])
                header['via'] = str(header['via'])
            feature += ' via:' + header['via']
        info = [feature, item[4]]
        param.append(info)

    libs.logger.log('all item : %d' % (len(res)))
    libs.logger.log('filte item : %d' % (counter))
    sql_statement = ('UPDATE web_fingerprint_result_10w_3000 '
                     'SET filter_headers = %s '
                     'WHERE id = %s')
    db_cursor.executemany(sql_statement, param)
    db_conn.commit()

    return


def test():
    _init()
    db_cursor = libs.common.get_value('db_cursor')
    db_conn = libs.common.get_value('db_conn')
    params = []
    with open('C:/Users/yuge/Desktop/20000.txt', 'r') as file:
        header = file.readline()
        header = file.readline()
        header = file.readline()
        line = file.readline()

        while line != '':
            ua_tag = ''
            resp_tag = ''
            web_fp_tag = ''
            tcpip_fp_tag = ''
            info = line.split('] ')[1].split('\n')[0]
            info_dict = eval(info)
            ok = False
            if 'ua_result' in info_dict.keys():
                if info_dict['ua_result']['tag'] == '????':
                    if info_dict['ua_result']['result'] == '0':
                        ua_tag = info_dict['ua_result']['feature']
                else:
                    ua_tag = info_dict['ua_result']['tag']
            if 'response_banner' in info_dict.keys():
                if info_dict['response_banner']['tag'] != '????':
                    resp_tag = info_dict['response_banner']['tag']
            if 'tcpip_fingerprint' in info_dict.keys():
                if info_dict['tcpip_fingerprint']['tag'] != '????':
                    tcpip_fp_tag = info_dict['tcpip_fingerprint']['tag']
            if 'web_fingerprint' in info_dict.keys():
                if info_dict['web_fingerprint']['tag'] != '????':
                    web_fp_tag = info_dict['web_fingerprint']['tag']
            line = file.readline()

            info = 'ua_tag:' + ua_tag + ' resp_tag:' + resp_tag + ' web_fp_tag:' + web_fp_tag + ' tcpip_fp_tag:' + tcpip_fp_tag
            ip = info_dict['ip']
            params.append((ip, info))

    sql_statement = ('INSERT INTO resource_infomation'
                     '(`ip`, `other_info`) '
                     'VALUE (%s, %s)')
    db_cursor.executemany(sql_statement, params)
    db_conn.commit()


if __name__ == '__main__':
    libs.common._init()
    libs.db.db_cursor_init()

    #print(select_all_response_header())
    #print(get_tcpip_fingerprint_by_clusterNum(0))
    #get_all_cluster_tags()
    #deal_web_fingerprint()
    test()
