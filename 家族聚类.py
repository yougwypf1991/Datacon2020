#coding=utf-8
"""
完成各DGA家族聚类，并对聚类模型
进行评价，得出最优类别数

TODO：聚类结果可视化，聚类模型评价结果
                        --2020.09.21

"""
import pandas as pd
import numpy as np
from sklearn.manifold import TSNE
from sklearn.cluster import KMeans
from sklearn.metrics import fowlkes_mallows_score
from sklearn.preprocessing import scale
import matplotlib.pyplot as plt


data = pd.read_excel(r'C:\Users\Administrator\Desktop\DNS恶意域名检测\2020Datacon.dns恶意域名\dns_2_question\feature_data.xlsx',
                     usecols=[0, 1, 2, 3, 4, 5, 6, 7, 8])
X = np.array(data)
X_scaled = scale(X)
kmeans = KMeans(n_clusters=5, random_state=42, max_iter=5000, n_init=10, tol=0.0001).fit(X_scaled)
labels_count = pd.Series(kmeans.labels_).value_counts()   #kmeans.labels:所有数据的类别 ; value_counts():各个类别对应的样本数量
centroids_vec = pd.DataFrame(kmeans.cluster_centers_)  #kmeans.cluster_centers_:质心向量
# concat = pd.concat([labels_count, centroids_vec], axis=1)   #concat:矩阵拼接函数。 axis默认为0，将参数1一行行插入到参数二；axis=1时，将参数1一列列插入参数二
#print('concat: ', concat)

result_Data = pd.concat([pd.DataFrame(X), pd.Series(kmeans.labels_)], axis=1)
# print(result_Data[:,[0]])
result_Data.columns = list(data.columns.values) + [u'所属类别数目']
# print(result_Data.columns)
result_Data.to_excel(r'C:\Users\Administrator\Desktop\DNS恶意域名检测\2020Datacon.dns恶意域名\dns_2_question\cluster_data.xlsx')

tsne = TSNE(n_components=2, init='random', random_state=170).fit(X_scaled)
df = pd.DataFrame(tsne.embedding_)
df['labels'] = kmeans.labels_
df1 = df[df['labels'] == 0]
df2 = df[df['labels'] == 1]
df3 = df[df['labels'] == 2]
df4 = df[df['labels'] == 3]
df5 = df[df['labels'] == 4]
# df6 = df[df['labels'] == 5]
fig = plt.figure(figsize=(9, 6))
plt.title('DGA Cluster')
plt.plot(df1[0], df1[1], 'ro', df2[0], df2[1], 'bx', df3[0], df3[1], 'g*',
         df4[0], df4[1], 'c+', df5[0], df5[1], 'm>')
# plt.plot(df1[0], df1[1], 'ro', df2[0], df2[1], 'bx', df3[0], df3[1], 'g*',
#          df4[0], df4[1], 'c+', df5[0], df5[1], 'm>', df6[0], df6[1], 'y.')
plt.show()

"""
模型数学评价部分：
"""
# for i in range(2, 7):
#     kmeans = KMeans(n_clusters=i, random_state=100).fit(X_scaled)
#     score = fowlkes_mallows_score()