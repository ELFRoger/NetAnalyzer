import scipy
import numpy as np
from tqdm import tqdm
import matplotlib.pyplot as plt
from sklearn.cluster import DBSCAN


class DBSCAN(DBSCAN):
    def k_dist_plot(self, data, k=4):
        """
        绘制k-dist图
        :param data: 向量化后的数据. [np.array or csr_matrix]
        :param k: 第k个近邻
        :return:
        """
        if isinstance(data, scipy.sparse.csr.csr_matrix):
            data = data.todense()
        k_list = []
        for i in tqdm(range(len(data))):
            dist = np.square(data[i, :] - data)
            dist = np.sqrt(np.sum(dist, axis=-1))
            this_k_dist = np.sort(dist)[k + 1]
            k_list.append(this_k_dist)

        k_list = sorted(k_list, reverse=True)
        plt.switch_backend('agg')
        plt.figure()
        plt.plot(range(len(k_list)), k_list, 'b-')
        plt.xlabel('points')
        plt.ylabel('k-dist')
        # plt.show()
        plt.savefig('./data/k-dist.png')
