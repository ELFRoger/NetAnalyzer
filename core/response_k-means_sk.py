#!/usr/bin/env python
# -*- coding: utf-8 -*-

from sklearn.feature_extraction.text import TfidfVectorizer
import joblib
from sklearn.cluster import KMeans
import nltk
from nltk.stem.snowball import SnowballStemmer
import re
from db_op import select_all_UA, select_all_response_header
import libs.common
import libs.logger
import libs.db
import matplotlib.pyplot as plt
from sklearn.manifold import TSNE
import numpy as np


def _init():
    libs.common._init()
    libs.db.db_cursor_init()


def get_feature():
    filePath = "responseData.csv"
    #处理csv文件  usecils为你想操作的列  skiprows为你想跳过的行 =1为跳过第一行
    feature_arr = np.loadtxt(filePath, usecols=np.arange(0, 42), delimiter=",", skiprows=1)

    return feature_arr


def kmeans_classer():

    # 需要进行聚类的文本集
    data = get_feature()
    libs.logger.log(data)
    libs.logger.log('k-means begining......')
    num_clusters = 50
    sse = []
    #手肘法，选k
    for clust in range(1000,1001):
        #clust = 100*clust
        libs.logger.log('clust ['+str(clust)+'] is begining.....')
        km_cluster = KMeans(n_clusters=clust, max_iter=100, n_init=40,
                            init='k-means++', n_jobs=7)
        km_cluster.fit(data)
        result = km_cluster.predict(data)
        sse.append(km_cluster.inertia_)
        libs.logger.log('clust [' + str(clust) + '] finish')
        libs.logger.log('clust ['+str(clust)+'] sse: ' + str(km_cluster.inertia_))
        f = open('response_' + str(clust) +'.txt', 'w')
        for i in range(len(result)):
            info = str(result[i])
            f.write(info)
        f.close()

    print("Predicting result: ", result)

    '''
        6、可视化
    '''
    # 使用T-SNE算法，对权重进行降维，准确度比PCA算法高，但是耗时长
    tsne = TSNE(n_components=2)
    decomposition_data = tsne.fit_transform(data)

    x = []
    y = []

    for i in decomposition_data:
        x.append(i[0])
        y.append(i[1])

    fig = plt.figure(figsize=(10, 10))
    ax = plt.axes()
    plt.scatter(x, y, c=km_cluster.labels_, marker="x")
    plt.xticks(())
    plt.yticks(())
    # plt.show()
    plt.savefig('./sample.png', aspect=1)

    '''
    '''

    print(sse)
    sse = [219456.88241477526, 210344.6742609666, 202510.30251572074, 193877.9982028553, 190193.06528536972, 185167.62407510882, 181378.35124433014, 176109.8874959115, 173725.72286034783, 169918.22260482085, 163231.54861425093, 162948.43114660977, 158810.5280173204, 155072.52220775714, 154264.30686423107, 151203.47277052913, 148986.94957191622, 145565.20444679252, 143292.76061348701, 141897.00501520524]
    X = range(50,250,10)
    X = range(100,1000,100)
    plt.xlabel('k')
    plt.ylabel('SSE')
    plt.plot(X,sse,'o-')
    plt.savefig('./sse.png')
    plt.show()
    '''
    n_clusters: 指定K的值
    max_iter: 对于单次初始值计算的最大迭代次数
    n_init: 重新选择初始值的次数
    init: 制定初始值选择的算法
    n_jobs: 进程个数，为-1的时候是指默认跑满CPU
    注意，这个对于单个初始值的计算始终只会使用单进程计算，
    并行计算只是针对与不同初始值的计算。比如n_init=10，n_jobs=40, 
    服务器上面有20个CPU可以开40个进程，最终只会开10个进程
    '''

    #joblib.dump(tfidf_vectorizer, 'tfidf_fit_result.pkl')
    #joblib.dump(km_cluster, 'km_cluster_fit_result.pkl')
    #程序下一次则可以直接load
    #tfidf_vectorizer = joblib.load('tfidf_fit_result.pkl')
    #km_cluster = joblib.load('km_cluster_fit_result.pkl')


_init()
kmeans_classer()
