#!/usr/bin/env python
# -*- coding: utf-8 -*-

import libs.logger
from traffic_analyze.traffic_analyzer import http_analyzer_by_dpkt,tcp_ip_fingerprint_analyze_by_dpkt
from clusters.tcpip_fingerprint_cluster import tcpip_fingerprint_do_clust
from clusters.web_fingerprint_cluster import web_fingerprint_do_clust
from clusters.UA_cluster import ua_do_clust
import numpy as np

def offline_traffic_deal(path,op):
    if op == 'http':
        http_analyzer_by_dpkt(pcapFolder=path)
    elif op=='fingerprint':
        tcp_ip_fingerprint_analyze_by_dpkt(pcapFolder=path)
    else:
        libs.logger.log("Ooops! no info can be analyzed")
    return


def train_cluster(model,datatype):
    if datatype == 'banner':
        ua_do_clust(model)
    elif datatype == 'web_fingerprint':
        web_fingerprint_do_clust(model)
    elif datatype == 'tcpip_fingerprint':
        tcpip_fingerprint_do_clust(model)
    else:
        libs.logger.log('no [%s] type data to do clust'.format(datatype))
    return


def predict_info(datatype,feature):
    return


def tagging_tcpip_fingerprint():
    filePath = "F:/models/tcpip_fingerprint_cosion_km_n300/fingerprint_cosion_k-means_20w_300.csv"
    feature_result = np.loadtxt(filePath, usecols=np.arange(3, 9), delimiter=",", skiprows=1)
    print(type(feature_result))

    return


def tagging_banner():
    return

def tagging_web_fingerprint():
    return


def tagging(type):
    if type == 'tcpip_fingerprint':
        tagging_tcpip_fingerprint()
    elif type == 'banner':
        tagging_banner()
    elif type == 'web_fingerprint':
        tagging_web_fingerprint()
    else:
        pass
    return


#tagging('tcpip_fingerprint')

