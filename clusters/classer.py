import numpy as np
import pandas as pd
import nltk
from nltk.stem.snowball import SnowballStemmer
import re
from sklearn import feature_extraction
from db_op import select_all_UA
from sklearn.feature_extraction.text import TfidfVectorizer
import libs.common
import libs.logger
import libs.db

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

stopwords = nltk.corpus.stopwords.words('english')
stemmer = SnowballStemmer('english')

def tokenize_and_stem(text):
    #首先分句，接着分词，而标点也会作为词例存在
    tokens=[word for sent in nltk.sent_tokenize(text) for word in nltk.word_tokenize(sent)]
    filtered_tokens=[]
    #过滤所有不含字母的词例（例如：数字、纯标点）
    for token in tokens:
        if re.search('[a-zA-Z]',token):
            filtered_tokens.append(token)
    stems=[stemmer.stem(t) for t in filtered_tokens]
    return stems

def tokenize_only(text):

    #首先分句，接着分词，而标点也会作为词例存在
    tokens=[word.lower() for sent in nltk.sent_tokenize(text) for word in nltk.word_tokenize(sent)]
    filtered_tokens=[]
    #过滤所有不含字母的词例（例如：数字、纯标点）
    for token in tokens:
        if re.search('[a-zA-Z]',token):
            filtered_tokens.append(token)
    return filtered_tokens


# 非常不 pythonic，一点也不！
# 扩充列表后变成了非常庞大的二维（flat）词汇表
totalvocab_stemmed = []
totalvocab_tokenized = []
for i in UA_list:
    if type(i)==list:
        i = ''.join(str(x) for x in i)
    allwords_stemmed = tokenize_and_stem(i)  # 对每个电影的剧情简介进行分词和词干化
    totalvocab_stemmed.extend(allwords_stemmed)  # 扩充“totalvocab_stemmed”列表

    allwords_tokenized = tokenize_only(i)
    totalvocab_tokenized.extend(allwords_tokenized)

vocab_frame=pd.DataFrame({'words':totalvocab_tokenized},index=totalvocab_stemmed)


print('there are '+ str(vocab_frame.shape[0]) + ' items in vocab_frame')

print(vocab_frame.head())


#define vectorizer parameters
tfidf_vectorizer = TfidfVectorizer(max_df=0.8, max_features=200000,
                                 min_df=0.2, stop_words='english',
                                 use_idf=True, tokenizer=tokenize_and_stem, ngram_range=(1,3))
#%time：Time execution of a Python statement or expression. https://ipython.readthedocs.io/en/stable/interactive/magics.html
#%time tfidf_matrix = tfidf_vectorizer.fit_transform(synopses) #fit the vectorizer to synopses
tfidf_matrix = tfidf_vectorizer.fit_transform(UA_list) #fit the vectorizer to synopses
#print(tfidf_matrix.shape)

terms = tfidf_vectorizer.get_feature_names()
from sklearn.metrics.pairwise import cosine_similarity
dist = 1 - cosine_similarity(tfidf_matrix)


from sklearn.cluster import KMeans
num_clusters = 10
km = KMeans(n_clusters=num_clusters)
#%time km.fit(tfidf_matrix)
km.fit(tfidf_matrix)
clusters = km.labels_.tolist()

from sklearn.externals import joblib
#uncomment the below to save your model
#since I've already run my model I am loading from the pickle
#joblib.dump(km, 'doc_cluster.pkl') 第一次运行时将注释打开，项目中会生成doc_cluster.pkl文件，之后运行的时候再注释掉这行就可以使用之前持久化的模型了
km = joblib.load('doc_cluster.pkl')
clusters = km.labels_.tolist()

# generates index for each item in the corpora (in this case it's just rank) and I'll use this for scoring later
ranks = []
for i in range(0,len(ip_list)):
    ranks.append(i)
#创建genres_list.txt文件，将https://github.com/brandomr/document_cluster/blob/master/genres_list.txt内容复制到这个文件中
genres = open('genres_list.txt').read().split('\n')
genres = genres[:100]
films = { 'ip': ip_list, 'rank': ranks, 'UA': UA_list, 'cluster': clusters, 'genre': genres }
frame = pd.DataFrame(films, index = [clusters] , columns = ['rank', 'title', 'cluster', 'genre'])
print(frame['cluster'].value_counts()) #number of films per cluster (clusters from 0 to 4)

grouped = frame['rank'].groupby(frame['cluster']) #groupby cluster for aggregation purposes
print(grouped.mean()) #average rank (1 to 100) per cluster

print("Top terms per cluster:")
print()
#sort cluster centers by proximity to centroid
order_centroids = km.cluster_centers_.argsort()[:, ::-1]
for i in range(num_clusters):
    print("Cluster %d words: " %i, end='') #%d功能是转成有符号十进制数 #end=''让打印不要换行
    for ind in order_centroids[i, :6]: #replace 6 with n words per cluster
        #b'...' is an encoded byte string. the unicode.encode() method outputs a byte string that needs to be converted back to a string with .decode()
        print('%s' %vocab_frame.loc[terms[ind].split(' ')].values.tolist()[0][0].encode('utf-8', 'ignore'), end=', ')
    print() #add whitespace
    print() #add whitespace
    print("Cluster %d titles: " %i, end='')
    for title in frame.loc[i]['title'].values.tolist():
        print(' %s,' %title, end='')
    print() #add whitespace
    print() #add whitespace
