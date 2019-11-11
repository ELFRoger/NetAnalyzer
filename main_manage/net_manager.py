#!/usr/bin/env python
# -*- coding: utf-8 -*-

import libs.logger
from traffic_analyze.traffic_analyzer import http_analyzer_by_dpkt,tcp_ip_fingerprint_analyze_by_dpkt
from clusters.fingerprint_cluster import fingerprint_do_clust
from clusters.response_cluster import response_do_clust
from clusters.UA_cluster import ua_do_clust

def offline_traffic_deal(path,op):
    if op == 'http':
        http_analyzer_by_dpkt(pcapFolder=path)
    elif op=='fingerprint':
        tcp_ip_fingerprint_analyze_by_dpkt(pcapFolder=path)
    else:
        libs.logger.log("Ooops! no info can be analyzed")
    return


def train_cluster(model,datatype):
    if datatype == 'request':
        ua_do_clust(model)
    elif datatype == 'response':
        response_do_clust(model)
    elif datatype == 'fingerprint':
        fingerprint_do_clust(model)
    else:
        libs.logger.log('no [%s] type data to do clust'.format(datatype))
    return


#def predict_info(datatype,feature):
