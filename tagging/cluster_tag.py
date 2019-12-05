#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
sys.path.append('../')

from mydb.db_op import select_all_response_info,get_ua_by_clusterNum,get_resp_banner_by_clusterNum
from mydb.db_op import get_tcpip_fingerprint_by_clusterNum, get_web_fingerprint_by_clusterNum,save_tag

import csv

from libs import common
from libs import db
import re
import config


def _init():
    common._init()
    db.db_cursor_init()


def tag_ua_banner(cluster_type):
    _init()
    feature_type = config.FEATRUE_TYPE['ua_banner']
    tags_list = {}

    mac = 0
    iphone = 0
    linux = 0
    windows = 0
    android = 0
    vivo = 0
    huawei = 0
    oppo = 0
    for i in range(1000):
        ua_banner_count,count = get_ua_by_clusterNum(i, cluster_type)
        #print(ua_banner_count)
        if ua_banner_count and ua_banner_count[0][0]:
            #print(str(i)+'\t'+str(ua_banner_count[0][1])+'\t'+str(count)+'\t',ua_banner_count[0][0])
            if '(' in ua_banner_count[0][0] and ')'in ua_banner_count[0][0]:
                p1 = re.compile(r'[(](.*?)[)]', re.S)
                tag = re.findall(p1,ua_banner_count[0][0])
                tags_list[i] = tag[0]
                #print(tag[0])
            else:
                tags_list[i] = ua_banner_count[0][0]
            print(i,tags_list[str(i)],ua_banner_count[0][0])
            '''
            if 'Mac' in ua_banner_count[0][0]:
                mac += count
            if 'Windows' in ua_banner_count[0][0]:
                windows += count
            if 'iPhone' in ua_banner_count[0][0]:
                iphone += count
            if 'Android' in ua_banner_count[0][0]:
                android += count
            if 'Linux' in ua_banner_count[0][0]:
                linux += count
            if 'vivo' in ua_banner_count[0][0]:
                vivo += count
            if 'HUAWEI' in ua_banner_count[0][0]:
                huawei += count
            if 'OPPO' in ua_banner_count[0][0]:
                oppo += count
    print('Mac Windows iPhone Android Linux vivo HUAWEI OPPO')
    print(mac,windows,iphone,android,linux,vivo,huawei,oppo)
    '''
    print(tags_list)
    #save_tag(feature_type,cluster_type,tags_list)
    return tags_list


def tag_resp_banner(cluster_type):
    _init()
    feature_type = config.FEATRUE_TYPE['response_banner']
    tags_list = {}

    for i in range(1000):
        resp_banner_count, count = get_resp_banner_by_clusterNum(i, cluster_type)
        if resp_banner_count and resp_banner_count[0][0]:
            tags_list[i] = resp_banner_count[0][0]
            #print(tags_list)
            print(str(i)+'\t'+str(resp_banner_count[0][1])+'\t'+str(count)+'\t',resp_banner_count[0][0])
    print(tags_list)
    #save_tag(feature_type, cluster_type, tags_list)
    return tags_list


def _load_fingerprint_db():
    fingerprint_db = {}
    with open('../fingerprint_database.csv','r') as fingerprint_file:
        csv_reder = csv.reader(fingerprint_file)
        csv_header = next(csv_reder)
        test = []
        for row in csv_reder:
            info = row[0].split(';')
            key_syn_win_ttl = '-'.join(str(x) for x in info[1:4])
            if key_syn_win_ttl not in fingerprint_db.keys():
                fingerprint_db[key_syn_win_ttl] = {}
            os_version = info[4] + '.'.join(str(x) for x in info[5:-1] if x!="N/A")
            confidece = float(info[7])
            fingerprint_db[key_syn_win_ttl][os_version] = confidece
            if info[4] not in test:
                test.append(info[4])
    print(test)
    #按各个可信度排序同一指纹能标识的os
    for key in fingerprint_db.keys():
        sorted(fingerprint_db[key],key=lambda x:x[1])
    return fingerprint_db


def _load_p0f_tool_fringerprint_db():
    with open('../p0f_fingerprint.txt', 'r') as file:
        line = file.readline()
        fp_list = []
        while line != '':
            if line.startswith('label'):
                label_ = line.split(':')[-2] + line.split(':')[-1].split('\n')[0]
                label = label_.split('(')[0]
                sig = file.readline()
                while True:
                    fp = []
                    if not sig.startswith('sig'):
                        break
                    else:
                        ttl = sig.split(':')[1]
                        mss = sig.split(':')[3]
                        win = sig.split(':')[4].split(',')[0]
                        if 'df' in sig:
                            df = '1'
                        else:
                            df = '0'
                        fp.append(label)
                        fp.append(ttl)
                        fp.append(mss)
                        fp.append(win)
                        fp.append(df)
                        # print fp
                        fp_list.append(fp)
                        sig = file.readline()
            line = file.readline()

    return fp_list


def _load_p0f_fringerprint_db():

    p0f_fingerprint = []
    with open('../p0f.fp', 'r') as file:
        line = file.readline()
        while line != '':
            if not line.startswith('#') and not line.startswith('\n'):
                fp = line.split('\n')[0]
                p0f_fingerprint.append(fp)
            line = file.readline()
    return p0f_fingerprint


def tag_tcpip_figerprint(cluster_type):
    _init()
    feature_type = config.FEATRUE_TYPE['tcpip_fingerprint']
    fingerprint_db = _load_fingerprint_db()
    p0f_fingerprint_db = _load_p0f_fringerprint_db()
    p0f_tool_fp_db = _load_p0f_tool_fringerprint_db()
    #print(p0f_fingerprint_db)
    tags_list = {}
    fingerprint_list = get_tcpip_fingerprint_by_clusterNum(cluster_type)
    count = 0
    no_tag = []

    for fingerprint in fingerprint_list:
        fuzzy = False
        cluster_num = fingerprint[0]
        ttl = fingerprint[3]
        if int(ttl) <= 32:
            fingerprint[3] = '32'
        elif int(ttl) > 32 and int(ttl) <= 64:
            fingerprint[3] = '64'
        elif int(ttl) > 64 and int(ttl) <= 128:
            fingerprint[3] = '128'
        else:
            fingerprint[3] = '255'

        feature = '-'.join(x for x in fingerprint[1:4])
        #print(feature)
        # 开源指纹库
        tag = ''
        if feature in fingerprint_db.keys():
            tag += list(fingerprint_db[feature])[0]
            if len(list(fingerprint_db[feature])) > 1:
                temp = list(fingerprint_db[feature])[1]
                if tag.find(temp) == -1:
                    print(tag, temp)
                    tag += '/' + list(fingerprint_db[feature])[1]
                else:
                    pass

        #p0f 工具 指纹库
        #select km_class,syn_len,win,ttl,df,rst,mss from
        #filter_fp = [feature[0], feature[3], feature[6] , feature[2]] # class, ttl, mss, win
        p0f_tool_tag = ''
        win = fingerprint[2]
        mss = fingerprint[6]
        ttl = fingerprint[3]
        df = fingerprint[4]

        for p0f_fp in p0f_tool_fp_db: # label, ttl, mss, winsize
            p0f_label = p0f_fp[0].rstrip()
            p0f_ttl = p0f_fp[1]
            p0f_mss = p0f_fp[2]
            p0f_win = p0f_fp[3]
            p0f_df = p0f_fp[4]
            #if ttl == p0f_ttl and df == p0f_df:
            if ttl == p0f_ttl:
                if p0f_mss == '*':
                    if p0f_win.find('*') != -1:
                        if p0f_fp[3] == '*':
                            fuzzy = True
                            if p0f_tool_tag.find(p0f_label) == -1:
                                p0f_tool_tag += p0f_label + '/'
                        else:
                            x = int(p0f_win.split('*')[-1])
                            if int(mss) * x == int(win):
                                if p0f_tool_tag.find(p0f_label) == -1:
                                    p0f_tool_tag += p0f_label + '/'
                    else:
                        if win == p0f_fp[3]:
                            if p0f_tool_tag.find(p0f_label) == -1:
                                p0f_tool_tag += p0f_label + '/'
                else:
                    if mss == p0f_mss:
                        if p0f_win.find('*') != -1:
                            if p0f_win == '*':
                                if p0f_tool_tag.find(p0f_label) == -1:
                                    p0f_tool_tag += p0f_label + '/'
                            else:
                                x = int(p0f_win.split('*')[-1])
                                if int(mss) * x == int(win):
                                    if p0f_tool_tag.find(p0f_label) == -1:
                                        p0f_tool_tag += p0f_label + '/'
                        else:
                            if win == p0f_win:
                                if p0f_tool_tag.find(p0f_label) == -1:
                                    p0f_tool_tag += p0f_label + '/'


        #p0f 二次开发 开源库指纹
        ttl_df_syn = fingerprint[3] + ':' + fingerprint[4] + ':' + fingerprint[1]
        win = fingerprint[2]
        mss = 'M' + fingerprint[6]
        t_win = '-'
        s_win = '-'
        p0f_tag = ''
        if int(fingerprint[6]) != -1:
            if int(fingerprint[6]) != 0 and int(win) % int(fingerprint[6]) == 0:
                s_win = "S" + str(int(win) // int(fingerprint[6])) + ':'
            elif int(win) % (int(fingerprint[6]) + 40) == 0:
                t_win = "T" + str(int(win) // (int(fingerprint[6]) + 40)) + ':'
        print(s_win, t_win)

        for p0f_fp in p0f_fingerprint_db:
            # win:ttl:DF:syn_len:mss..:os:版本
            os_info = p0f_fp.split(':')[-2]
            version = p0f_fp.split(':')[-1]
            if ttl_df_syn in p0f_fp and mss in p0f_fp:
                if p0f_fp.startswith('*'):
                    if p0f_tag.find(os_info) == -1:
                        p0f_tag += os_info + version + '/'
                    else:
                        p0f_tag += '/' + version
                    print(win, ttl_df_syn, mss)
                else:
                    if p0f_fp.startswith(win) or p0f_fp.startswith(t_win) or p0f_fp.startswith(s_win):
                        if p0f_tag.find(os_info) == -1:
                            p0f_tag += os_info + version + '/'
                        else:
                            p0f_tag += '/' + version
                        print(win, ttl_df_syn, mss)
            elif ttl_df_syn in p0f_fp and 'M*' in p0f_fp:
                if p0f_fp.startswith('*'):
                    if p0f_tag.find(os_info) == -1:
                        p0f_tag += os_info + version + '/'
                    else:
                        p0f_tag += '/' + version
                    print('*', win, ttl_df_syn, 'M*')
                else:
                    if p0f_fp.startswith(win) or p0f_fp.startswith(t_win) or p0f_fp.startswith(s_win):
                        if p0f_tag.find(os_info) == -1:
                            p0f_tag += os_info + version + '/'
                        else:
                            p0f_tag += '/' + version
                        print(p0f_fp.startswith(t_win), p0f_fp.startswith(s_win), win, ttl_df_syn, mss, 'm*')

        #确定标签
        if p0f_tag != '':
            if tag != '' and tag.find('/') == -1:
                tags_list[cluster_num] = tag
            else:
                tags_list[cluster_num] = p0f_tag
            print(ttl_df_syn, fingerprint, tags_list[cluster_num], '---p0f', tag)
        elif p0f_tag == '' and p0f_tool_tag != '':
            if tag != '' and tag.find('/') == -1:
                tags_list[cluster_num] = tag
            elif tag != '' and (tag.count('Android') == 2 or tag.count('Windows') == 2 ):
                tags_list[cluster_num] = tag
            else:
                tags_list[cluster_num] = p0f_tool_tag
            print(ttl_df_syn, fingerprint, tags_list[cluster_num], '---p0f_tool', tag)
        elif p0f_tag == '' and p0f_tool_tag == '' and tag != '':
            tags_list[cluster_num] = tag
            print(ttl_df_syn, fingerprint, tags_list[cluster_num], '---tag ')
        else:
            if fingerprint[0] not in no_tag:
                no_tag.append(fingerprint[0])
            count += 1
            print(ttl_df_syn, fingerprint, '????', tag)
            pass

    print(count, len(no_tag), no_tag)

    #save_tag(feature_type, cluster_type, tags_list)
    return tags_list


def tag_web_fingerprint(cluster_type):
    _init()
    feature_type = config.FEATRUE_TYPE['web_fingerprint']
    tags_list = {}

    for i in range(3000):
        web_fingerprint_count, count = get_web_fingerprint_by_clusterNum(i, cluster_type)
        if web_fingerprint_count and web_fingerprint_count[0][0]:
            tags_list[i] = web_fingerprint_count[0][0]
            #print(tags_list)
            print(str(i)+'\t'+str(web_fingerprint_count[0][1])+'\t'+str(count)+'\t',web_fingerprint_count[0][0])
    #print(tags_list)
    save_tag(feature_type, cluster_type, tags_list)
    return tags_list


def tag_cluster():
    _init()
    keams = 'kmeans'
    cosion = 'cosion'
    tag_ua_banner(keams)
    tag_resp_banner(keams)
    tag_tcpip_figerprint(keams)
    tag_web_fingerprint(keams)
    tag_ua_banner(cosion)
    tag_resp_banner(cosion)
    tag_tcpip_figerprint(cosion)
    tag_web_fingerprint(cosion)


if __name__ == '__main__':
    _init()
    keams = 'kmeans'
    cosion = 'cosion'
    #tag_ua_banner(keams)
    #tag_ua_banner(cosion)

    #tag_resp_banner(keams)
    #tag_web_fingerprint(keams)
    #tag_web_fingerprint(cosion)

    #tag_tcpip_figerprint(keams)
    #tag_tcpip_figerprint(cosion)

    tag_tcpip_figerprint(keams)
    tag_tcpip_figerprint(cosion)



