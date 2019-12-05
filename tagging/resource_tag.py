#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
sys.path.append('../')

import joblib
from traffic_analyze.dpkt_engine import dpkt_http, dpkt_tcpip_fingerprint
from config import response_header_key
from clusters.banner_cluster import tokenize_only,get_response_header,get_UA
from mydb.db_op import get_all_cluster_tags
import time


def get_feature_from_pcap(filename):
    http_list = dpkt_http(filename)
    tcpip_fingerprint_list = dpkt_tcpip_fingerprint(filename)

    feature_dict = {}
    for http in http_list:
        # print(http['headers'])
        if http['src'] not in feature_dict.keys():
            feature_dict[http['src']] = {}
        if http['type'] == 'request':
            if http['headers']:
                header = http['headers']
                if 'user-agent' in header.keys():
                    ua_banner = header['user-agent']
            else:
                ua_banner = ''
            feature_dict[http['src']]['ua_banner'] = ua_banner

        if http['type'] == 'response':

            if http['headers']:
                # 提取response banner
                feature = ''
                header = http['headers']
                if 'server' in header.keys():
                    if type(header['server']) == list:
                        header['server'] = str(header['server'])
                    feature += 'server:' + header['server']
                if 'www-authenticate' in header.keys():
                    if type(header['www-authenticate']) == list:
                        header['www-authenticate'] = str(header['www-authenticate'])
                    feature += 'www-authenticate:' + header['www-authenticate']
                if 'x-powered-by' in header.keys():
                    if type(header['x-powered-by']) == list:
                        header['x-powered-by'] = str(header['x-powered-by'])
                    feature += 'x-powered-by:' + header['x-powered-by']
                response_banner = feature

                # 提取response 指纹信息

                web_fingerprint = []
                for key in response_header_key:
                    if key in header.keys():
                        if key == 'content-length':
                            try:
                                if isinstance(header[key], list):
                                    web_fingerprint.append(int(header[key][0]))
                                elif header[key]:
                                    web_fingerprint.append(int(header[key]))
                                else:
                                    web_fingerprint.append(1)
                            except:
                                web_fingerprint.append(1)
                        else:
                            web_fingerprint.append(1)
                    else:
                        web_fingerprint.append(0)
            else:
                response_banner = ''
                web_fingerprint = [0] * 41
            feature_dict[http['src']]['response_banner'] = response_banner
            feature_dict[http['src']]['web_fingerprint'] = [web_fingerprint]

    for tcpip_fingerprint in tcpip_fingerprint_list:
        #fingerprint = [ts, inet_to_str(ip.src), tcp.sport, syn_len, win, ttl, df, rst, mss]
        if tcpip_fingerprint[1] not in feature_dict.keys():
            feature_dict[tcpip_fingerprint[1]] = {}
        feature_dict[tcpip_fingerprint[1]]['tcpip_fingerprint'] = [tcpip_fingerprint[3:]]

    return feature_dict


def load_cluster_model():

    models = {}
    ua_banner_tfidf_model = joblib.load('E:/roger/models/request_banner_cosion_km_n1000/ua_tfidf_cosion_result.pkl')
    ua_banner_model = joblib.load('E:/roger/models/request_banner_cosion_km_n1000/ua_cosion_km_cluster_fit_result.pkl')
    response_banner_tfidf_model = joblib.load('E:/roger/models/response_banner_cosion_km_n1000/response_tfidf_cosion_result.pkl')
    response_banner_model = joblib.load('E:/roger/models/response_banner_cosion_km_n1000/response_cosion_km_cluster_fit_result.pkl')
    web_fingerprint_model = joblib.load('E:/roger/models/web_fingerprint_cosion_km_n1000/web_fingerprint_cosion_km_cluster_fit_result.pkl')
    tcpip_fingerprint_model = joblib.load('E:/roger/models/tcpip_fingerprint_cosion_km_n300/fingerprint_cosion_km_cluster_fit_result.pkl')

    models['ua_banner_tfidf_model'] = ua_banner_tfidf_model
    models['ua_banner_model'] = ua_banner_model
    models['response_banner_tfidf_model'] = response_banner_tfidf_model
    models['response_banner_model'] = response_banner_model
    models['web_fingerprint_model'] = web_fingerprint_model
    models['tcpip_fingerprint_model'] = tcpip_fingerprint_model
    return models


class ua_banner_cluster:
    train_data = []
    cluster_models = []
    tfidf_matrix = []

    def __init__(self, cluster_models):
        ip_list, self.train_data = get_UA(num=100000)
        self.cluster_models = cluster_models
        self.tfidf_matrix = self.cluster_models['ua_banner_tfidf_model'].fit_transform(self.train_data)

    def update(self, feature):
        if feature in self.train_data:
            pass
        else:
            self.train_data.append(feature)
            self.tfidf_matrix = self.cluster_models['ua_banner_tfidf_model'].fit_transform(self.train_data)


class resp_banner_cluster:
    train_data = []
    cluster_models = []
    tfidf_matrix = []

    def __init__(self, cluster_models):
        ip_list, self.train_data = get_response_header()
        self.cluster_models = cluster_models
        self.tfidf_matrix = self.cluster_models['response_banner_tfidf_model'].fit_transform(self.train_data)

    def update(self, feature):
        if feature in self.train_data:
            pass
        else:
            self.train_data.append(feature)
            self.tfidf_matrix = self.cluster_models['response_banner_tfidf_model'].fit_transform(self.train_data)


def predict_resource(feature, cluster_models, ua_banner_cluster, resp_banner_cluster):
    if 'ua_banner' in feature.keys():
        if feature['ua_banner'] in ua_banner_cluster.train_data:
            index = ua_banner_cluster.train_data.index(feature['ua_banner'])
            tfidf_matrix = ua_banner_cluster.tfidf_matrix
        else:
            ua_banner_cluster.update(feature['ua_banner'])
            index = ua_banner_cluster.train_data.index(feature['ua_banner']) -1
            tfidf_matrix = ua_banner_cluster.tfidf_matrix
        ua_result = cluster_models['ua_banner_model'].predict(tfidf_matrix[index])
        print('ua_result:',ua_result)
    if 'response_banner' in feature.keys():
        if feature['response_banner'] in resp_banner_cluster.train_data:
            index = resp_banner_cluster.train_data.index(feature['response_banner'])
            tfidf_matrix = resp_banner_cluster.tfidf_matrix
        else:
            resp_banner_cluster.update(feature['response_banner'])
            index = resp_banner_cluster.train_data.index(feature['response_banner']) -1
            tfidf_matrix = resp_banner_cluster.tfidf_matrix
        ua_result = cluster_models['response_banner_model'].predict(tfidf_matrix[index])
        print('response_banner_result:',ua_result)

    if 'web_fingerprint' in feature.keys():
        web_fingerprint_result = cluster_models['web_fingerprint_model'].predict(feature['web_fingerprint'])
        print('web_fingerprint_result:', web_fingerprint_result)
    if 'tcpip_fingerprint' in feature.keys():
        tcpip_fingerprint_result = cluster_models['tcpip_fingerprint_model'].predict(feature['tcpip_fingerprint'])
        print('tcpip_fingerprint_result:', tcpip_fingerprint_result)


def tagging_resource():
    print(str(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())), '1.begin')
    tag_dict = get_all_cluster_tags()
    feature_list = get_feature_from_pcap('../test.pcap')
    print(str(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())), '2.begin')
    cluster_models = load_cluster_model()
    global ua_banner_cluster
    global resp_banner_cluster
    ua_banner_cluster = ua_banner_cluster(cluster_models)
    resp_banner_cluster = resp_banner_cluster(cluster_models)
    print(str(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())), '3.begin')
    count = 0
    for ip, feature in feature_list.items():
        count += 1
        print(ip)
        predict_resource(feature, cluster_models,
                         ua_banner_cluster=ua_banner_cluster,
                         resp_banner_cluster=resp_banner_cluster)
        '''
        if 'ua_banner' in feature.keys():
            print(ip, ' ua_banner***************', feature['ua_banner'])
            predict_resource(feature, cluster_models, banner_cluster=ua_banner_cluster)
        if 'response_banner' in feature.keys():
            print(ip, ' response_banner***************',feature['response_banner'])
            predict_resource(feature, cluster_models, banner_cluster=resp_banner_cluster)
        if 'web_fingerprint' in feature.keys():
            print(ip, ' web_fingerprint***************',feature['web_fingerprint'])
            predict_resource(feature, cluster_models, banner_cluster='')
        if 'tcpip_fingerprint' in feature.keys():
            print(ip,' tcpip_fingerprint***************',feature['tcpip_fingerprint'])
            predict_resource(feature, cluster_models, banner_cluster='')
        '''
        if count == 10:
            break

    print(str(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())), '4.begin')


if __name__ == '__main__':
    tagging_resource()

