#!/usr/bin/env python
# -*- coding: utf-8 -*-

from sklearn.feature_extraction.text import TfidfVectorizer
import joblib
from sklearn.cluster import KMeans
import nltk
from nltk.stem.snowball import SnowballStemmer
import re
from db_op import select_all_UA
import libs.common
import libs.logger
import libs.db
import matplotlib.pyplot as plt

def _init():
    libs.common._init()
    libs.db.db_cursor_init()

_init()

UA_info  = select_all_UA()

ip_list = []
UA_list = []
for item in UA_info:
    ip_list.append(item['ip'])
    UA_list.append(item['UA'])

for i in range(len(UA_list)):
    if type(UA_list[i])==list:
        temp = ''.join(str(x) for x in UA_list[i])
        UA_list[i] = temp

def tokenize_only(text):
    #首先分句，接着分词，而标点也会作为词例存在
    tokens=[word for sent in nltk.sent_tokenize(text) for word in nltk.word_tokenize(sent)]
    '''
    filtered_tokens=[]
    #过滤所有不含字母的词例（例如：数字、纯标点）
    for token in tokens:
        if re.search('[a-zA-Z]',token):
            filtered_tokens.append(token)
    return filtered_tokens
    '''
    return tokens

tfidf_vectorizer = TfidfVectorizer(tokenizer=tokenize_only,lowercase=False)
'''
tokenizer: 指定分词函数
lowercase: 在分词之前将所有的文本转换成小写，因为涉及到中文文本处理，
所以最好是False
'''

text_list = ["今天天气真好啊啊啊啊", "小明上了清华大学",
             "我今天拿到了Google的Offer", "清华大学在自然语言处理方面真厉害"]
# 需要进行聚类的文本集
tfidf_matrix = tfidf_vectorizer.fit_transform(UA_list)
libs.logger.log('k-means begining......')
num_clusters = 50
sse = []
#手肘法，选k
for clust in range(20,num_clusters):
    libs.logger.log('clust ['+str(clust)+'] is begining.....')
    km_cluster = KMeans(n_clusters=clust, max_iter=300, n_init=40,
                        init='k-means++', n_jobs=5)
    # 返回各自文本的所被分配到的类索引
    km_cluster.fit(tfidf_matrix)
    result = km_cluster.predict(tfidf_matrix)
    libs.logger.log('clust [' + str(clust) + '] finish')
    sse.append(km_cluster.inertia_)

    f = open('result_' + str(clust) +'.txt', 'w')
    for i in range(len(UA_list)):
        info = str(result[i]) + '\t' + ip_list[i] + '\t' + UA_list[i] + '\n'
        f.write(info)

    print("Predicting result: ", result)
    libs.logger.log('clust:' + str(clust) + 'is begining.....')

X = range(20,50)
plt.xlabel('k')
plt.ylabel('SSE')
plt.plot(X,sse,'o-')
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

