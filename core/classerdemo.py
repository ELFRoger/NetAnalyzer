#!/usr/bin/env python
# -*- coding: utf-8 -*-

from sklearn.feature_extraction.text import TfidfVectorizer
import joblib
from sklearn.cluster import KMeans
import nltk
import re
from db_op import select_all_UA, select_all_response_header
import libs.common
import libs.logger
import libs.db
import matplotlib.pyplot as plt
from sklearn.manifold import TSNE
import cosion_kmeans


def _init():
    libs.common._init()
    libs.db.db_cursor_init()


def get_UA(num):
    UA_info  = select_all_UA(num)
    ip_list = []
    UA_list = []
    for item in UA_info:
        ip_list.append(item['ip'])
        UA_list.append(item['UA'])

    for i in range(len(UA_list)):
        if type(UA_list[i]) == list:
            temp = ''.join(str(x) for x in UA_list[i])
            UA_list[i] = temp
    return ip_list, UA_list


def get_response_header():
    header_info = select_all_response_header()

    ip_list = []
    header_list = []
    for item in header_info:
        ip_list.append(item['ip'])
        header_list.append(item['header'])

    return ip_list, header_list


def tokenize_only(text):
    #首先分句，接着分词，而标点也会作为词例存在
    tokens = [word for sent in nltk.sent_tokenize(text) for word in nltk.word_tokenize(sent)]

    filtered_tokens=[]
    #过滤所有不含字母的词例（例如：数字、纯标点）
    for token in tokens:
        if re.search('[a-zA-Z]', token):
            filtered_tokens.append(token)
    return filtered_tokens
    #return tokens


def kmeans_classer(original_info,ip_list):
    '''
    tokenizer: 指定分词函数
    lowercase: 在分词之前将所有的文本转换成小写，因为涉及到中文文本处理，
    所以最好是False
    '''
    tfidf_vectorizer = TfidfVectorizer(tokenizer=tokenize_only,lowercase=False)

    # 需要进行聚类的文本集
    tfidf_matrix = tfidf_vectorizer.fit_transform(original_info)
    word = tfidf_vectorizer.get_feature_names()
    tfidf_weight = tfidf_matrix.toarray()
    libs.logger.log("word feature length: {}".format(len(word)))
    libs.logger.log(word)
    libs.logger.log('k-means begining......')
    num_clusters = 50
    sse = []
    #手肘法，选k
    for clust in range(1000,1001):
        #clust = 100*clust
        libs.logger.log('clust ['+str(clust)+'] is begining.....')
        km_cluster = KMeans(n_clusters=clust, max_iter=100, n_init=40,
                            init='k-means++', n_jobs=7)
        km_cluster.fit(tfidf_matrix)
        result = km_cluster.predict(tfidf_matrix)     # 返回各自文本的所被分配到的类索引
        sse.append(km_cluster.inertia_)
        libs.logger.log('clust [' + str(clust) + '] finish')
        libs.logger.log('clust ['+str(clust)+'] sse: ' + str(km_cluster.inertia_))
        f = open('result_10w_' + str(clust) +'.txt', 'w')
        for i in range(len(original_info)):
            info = str(result[i]) + '\t' + ip_list[i] + '\t' + original_info[i] + '\n'
            f.write(info)
        f.close()

    print("Predicting result: ", result)

    '''
        6、可视化
    '''
    # 使用T-SNE算法，对权重进行降维，准确度比PCA算法高，但是耗时长
    tsne = TSNE(n_components=2)
    decomposition_data = tsne.fit_transform(tfidf_weight)

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


def DBscan_classer(original_info, ip_list):
    tfidf_vectorizer = TfidfVectorizer(tokenizer=tokenize_only, lowercase=False)
    tfidf_matrix = tfidf_vectorizer.fit_transform(original_info)
    libs.logger.log('DBSCAN begining......')

    return


def cosion_kmeans(original_info,ip_list,n_clust):
    cluster = cosion_kmeans.CosineMeans()
    cluster.set_n_cluster(n_clust)

    tfidf_vectorizer = TfidfVectorizer(tokenizer=tokenize_only, lowercase=False)
    # 需要进行聚类的文本集
    tfidf_matrix = tfidf_vectorizer.fit_transform(original_info)
    word = tfidf_vectorizer.get_feature_names()
    tfidf_weight = tfidf_matrix.toarray()
    #log
    libs.logger.log("word feature length: {}".format(len(word)))
    libs.logger.log(word)
    libs.logger.log('k-means begining......')
    #fit and predict
    cluster.fit(tfidf_matrix)
    result = cluster.predict(tfidf_matrix)
    sse = cluster.inertia_
    libs.logger.log('k-means finished sse:' + str(sse))
    f = open('result_cosion_' + str(n_clust) + '.txt', 'w')
    for i in range(len(original_info)):
        info = str(result[i]) + '\t' + ip_list[i] + '\t' + original_info[i] + '\n'
        f.write(info)
    f.write(str(sse))
    f.close()


_init()
ip_list, original_info = get_UA(100000)
#kmeans_classer(original_info, ip_list)
cosion_kmeans(original_info, ip_list, 100)
'''

sse = [219456.88241477526, 210344.6742609666, 202510.30251572074, 193877.9982028553, 190193.06528536972, 185167.62407510882, 181378.35124433014, 176109.8874959115, 173725.72286034783, 169918.22260482085,
       163231.54861425093, 162948.43114660977, 158810.5280173204, 155072.52220775714, 154264.30686423107, 151203.47277052913, 148986.94957191622, 145565.20444679252, 143292.76061348701, 141897.00501520524,
       130733.68913128684, 118443.77205879042, 108691.0812558125, 100866.62825419528, 95450.26140386396]
sse = [185167.62407510882, 151203.47277052913, 130733.68913128684, 118443.77205879042, 108691.0812558125, 100866.62825419528, 95450.26140386396]
sub = list()
for i in range(1,len(sse)):
    sub.append(sse[i]-sse[i-1])
print(sub)
#X = [x for x in range(50,250,10)]
#X.extend([x for x in range(300,800,100)])
X = range(100, 800, 100)
print(X)
plt.xlabel('k')
plt.ylabel('SSE')
plt.plot(X,sse,'o-')
plt.savefig('./sse_all.png')
plt.show()
'''