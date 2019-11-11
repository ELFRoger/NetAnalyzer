from scipy import sparse
from scipy.stats import rv_discrete
from sklearn.cluster import KMeans
from sklearn.metrics import pairwise_distances_argmin_min
from sklearn.utils import check_random_state
import numpy as np


class CosineMeans(KMeans):

    def __init__(self, n_clusters=8, init='k-means++', max_iter=300, tol=1e-4,
                 verbose=0, random_state=None, copy_x=True, n_jobs=1, **_):

        super(CosineMeans, self).__init__(n_clusters=n_clusters, init=init, n_init=1,
                                          max_iter=max_iter,  tol=tol, verbose=verbose,
                                          n_jobs=n_jobs, random_state=random_state,
                                          copy_x=copy_x, precompute_distances=False)
    def set_n_cluster(self, n_clust):
        self.n_clusters = n_clust

    def fit(self, X, y=None):
        random_state = check_random_state(self.random_state)
        #X = self._check_fit_data(X)

        # Init CosineMeans
        if (isinstance(self.init, np.ndarray)):
            self.cluster_centers_ = self.init
        elif (self.init == 'random'):
            idx = random_state.randint(X.shape[0], (self.n_clusters,))
            self.cluster_centers_ = X[idx].A if sparse.issparse(X) else X[idx]
        elif (self.init == 'k-means++'):
            self.cluster_centers_ = self._kmeanspp(X=X, random_state=random_state)
        else:
            raise ValueError('Unknown param passed to `init`: {}. Allowed values are "random", "k-means++" or an ndarray')

        # Run CosineMeans
        centroids = np.zeros((self.n_clusters, X.shape[1]))#sparse.csr_matrix((self.n_clusters, X.shape[1]))
        for _ in range(self.max_iter):
            clustering, distances = pairwise_distances_argmin_min(X=X, Y=self.cluster_centers_, metric='cosine')
            # http://stackoverflow.com/questions/29629821/sum-over-rows-in-scipy-sparse-csr-matrix

            # Todo: This really needs improvement
            for yi in np.unique(clustering):
                row_idx = np.where(clustering==yi)[0]

                if (sparse.issparse(X)):
                    centroids[yi] = np.asarray(X[row_idx].multiply(1/len(row_idx)).sum(axis=0))
                else:
                    centroids[yi] = np.multiply(X[row_idx], 1/len(row_idx)).sum(axis=0)

            # Convergence check
            if (np.all(np.abs(self.cluster_centers_-centroids) < self.tol)):
                break
            self.cluster_centers_ = centroids
        self.cluster_centers_ = centroids
        self.labels_ = clustering

        return self

    def fit_predict(self, X, y=None):
        self.fit(X, y)

        return self.predict(X)

    def predict(self, X):
        clustering, _ = pairwise_distances_argmin_min(X=X, Y=self.cluster_centers_, metric='cosine')

        self.labels_ = clustering

        return self.labels_

    def _kmeanspp(self, X, random_state):
        # Based on: https://en.wikipedia.org/wiki/K-means%2B%2B
        Xp = type(X)(X, shape=X.shape, dtype=X.dtype, copy=True) if sparse.issparse(X) else np.copy(X)
        print(type(Xp))
        idx = random_state.randint(X.shape[0], size=(1,), dtype=Xp.indptr.dtype)[0]

        centroids = Xp[idx]
        Xp = self.delete_row_csr(Xp, idx) if sparse.issparse(Xp) else np.delete(Xp, idx, axis=0)

        while (centroids.shape[0] < self.n_clusters):
            clustering, distances = pairwise_distances_argmin_min(X=Xp, Y=centroids, metric='cosine')

            # Calculate weighted probability distribution
            d = np.power(distances, 2)
            p = d / d.sum()

            dist = rv_discrete(values=(np.arange(Xp.shape[0]), p), seed=random_state)

            # Choose next centroid
            idx = dist.rvs()
            centroids = sparse.vstack((centroids, Xp[idx])) if sparse.issparse(Xp) else np.concatenate((centroids, Xp[idx].reshape(1, -1)), axis=0)

            # Delete center from `Xp`
            Xp = self.delete_row_csr(Xp, idx) if sparse.issparse(Xp) else np.delete(Xp, idx, axis=0)

        return centroids

    def delete_row_csr(self, mat, i): # Courtesy of http://stackoverflow.com/questions/13077527/is-there-a-numpy-delete-equivalent-for-sparse-matrices
        if (not isinstance(mat, sparse.csr_matrix)):
            raise ValueError("works only for CSR format -- use .tocsr() first")

        n = mat.indptr[i+1] - mat.indptr[i]
        if n > 0:
            mat.data[mat.indptr[i]:-n] = mat.data[mat.indptr[i+1]:]
            mat.data = mat.data[:-n]
            mat.indices[mat.indptr[i]:-n] = mat.indices[mat.indptr[i+1]:]
            mat.indices = mat.indices[:-n]
        mat.indptr[i:-1] = mat.indptr[i+1:]
        mat.indptr[i:] -= n
        mat.indptr = mat.indptr[:-1]
        mat._shape = (mat._shape[0]-1, mat._shape[1])

        return mat