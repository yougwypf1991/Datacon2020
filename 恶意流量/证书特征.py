# -*- coding: UTF-8 -*-
'''

根据rdnSequence的值，提取到叶子证书中的Subject字段和Issuer字段
对每个样本建立词袋模型，再将词频编码为特征向量，使用朴素贝叶斯分类
分为三个函数：
    def getFields  获取单个文件内的Subject和Issuer字段
    def add_key    将索引字典中不存在的key添加进字典
    def index_bag  建立索引字典
    def token      统计词频
    def classify   进行贝叶斯分类

'''

import os
import json
import pandas as pd

from sklearn.naive_bayes import BernoulliNB     #伯努利型贝叶斯
from sklearn.model_selection import train_test_split
import numpy as np
import matplotlib.pyplot as plt

def getFields(file):
    '''
    获取subject和issuer字段
    :param file:
    :return: subOrIsu 单个pcap文件内所有的subject和issuer字段
    '''

    cmd = 'tshark -r {file} -T json  -e x509sat.printableString'    #调用tshark的终端命令
    res = os.popen(cmd.format(file=file))
    data = str(res.buffer.read().decode(encoding='utf8'))   #解码命令执行结果，结果中有中文，需要使用encoding='utf8'才可正确解析
    json_data = ''  #存储json解码内容
    try:
        json_data = json.loads(data)
    except:
        print('Wrong File: ', file)
    subOrIsu = []
    for tmp in json_data:
        x509sat = tmp.get('_source').get('layers')
        if x509sat:
            subOrIsu.extend(x509sat.get('x509sat.printableString'))   #获取所有的'x509sat.printableString'，即subject和issuer字段
    return subOrIsu


def add_key(data, bag):
    '''
    将索引字典中不存在的key添加进字典
    :param data: 单个pcap文件内所有的subject和issuer字段组成的列
    :param bag: 索引字典
    :return:
    '''
    for tmp in data:
        if tmp.lower() not in bag.keys():
            bag[tmp.lower()] = 0
            print('索引字典添加新词: ', tmp.lower())


def index_bag():
    '''
    建立索引字典
    :param:
    :return:     terms：当词汇文件存在时，存储了所有subject和issuer字段的列表
    '''

    terms = {}  #用于存储从词汇文件中读取的字段
    if os.path.exists(train_path + '\\bagging\\bag.txt'):   #若词汇文件存在则读取词汇文件内容并建立索引字典
        with open(train_path + '\\bagging\\bag.txt', 'r') as r_f:
            dic = r_f.readlines()
            for key in dic:
                terms[key.strip('\n')] = 0

    else:   #若词汇文件不存在，则循环读取所有的pcap文件建立索引字典，并将字典的keys写入bag.txt
        for tmp in os.listdir(white_path):
            tmp = white_path + '\\' + tmp
            data = getFields(tmp)
            add_key(data, terms)

        for tmp in os.listdir(black_path):
            tmp = black_path + '\\' + tmp
            data = getFields(tmp)
            add_key(data, terms)

        with open(train_path + '\\bagging\\bag.txt', 'w') as w_f:
            for key in terms.keys():
                w_f.write(key + '\n')

    return terms


def token(file, data):
    '''
    统计词频
    :param file: 当前统计词频的文件
    :param data: file文件中所有的subject和issuer字段
    :param terms: 索引字典，values均为0
    :return:
    '''
    bag = index_bag()
    for key in data:
        bag[key.strip('\n').lower()] += 1
    bag_df = pd.DataFrame(bag, index=[0])
    bag_df = pd.concat([pd.DataFrame({'file': file}, index=[0]), bag_df], axis=1)   #拼接成 文件名 词频 形式的矩阵，带上文件名索引方便查看数据进行比对
    if os.path.exists(csv_path):    #若词频文件不存在，则在写入词频文件时，需要带header参数，若存在则不需要带header参数
        bag_df.to_csv(csv_path, index=False, header=False, mode='a', sep=',')
    else:
        bag_df.to_csv(csv_path, index=False, header=bag_df.keys(), mode='a', sep=',')


def classify(X, Y):
    '''
    贝叶斯分类函数
    :param X: 训练词频矩阵
    :param Y: 标签矩阵
    :return:
    '''
    # X = shuffle(X)
    X_train, X_test, Y_train, Y_test = train_test_split(X, Y, random_state=11, test_size=0.1)
    alphas = np.logspace(-3, 5, num=20)
    binarizes=np.linspace(-50, 20, endpoint=True, num=70)
    train_scores = []
    test_scores = []
    highest = 0
    for alpha in alphas:
        for binarize in binarizes:
            # print(alpha, binarize)
            cls = BernoulliNB(alpha=alpha)
            cls.fit(X_train, Y_train)
            train_score = cls.score(X_train, Y_train)
            test_score = cls.score(X_test, Y_test)
            test_scores.append(test_score)
            # train_scores.append(train_score)
            # test_scores.append(test_score)
            if test_score > highest:
                highest = test_score
                print('当前最高训练分数: ', train_score)
                print('当前最高测试分数: ', test_score)
                print('参数值 alpha:', alpha, 'binarize:',binarize)



if __name__ == '__main__':
    white_path = r'C:\Users\Administrator\Desktop\DNS恶意域名检测\Datacon2020加密流量检测\eta_1\train\white'
    black_path = r'C:\Users\Administrator\Desktop\DNS恶意域名检测\Datacon2020加密流量检测\eta_1\train\black'
    csv_path   = r'C:\Users\Administrator\Desktop\DNS恶意域名检测\Datacon2020加密流量检测\eta_1\train\csv\train.csv'
    train_path = r'C:\Users\Administrator\Desktop\DNS恶意域名检测\Datacon2020加密流量检测\eta_1\train'

    '''
    建立索引词袋
    '''

    '''
    统计词频    每个文件统计成一行，保存在train.csv
    '''
    if os.path.exists(csv_path):
        X = pd.read_csv(csv_path, index_col=0)
    else:
        files_white = os.listdir(white_path)
        for tmp in files_white:  #统计白样本的词频
            file = white_path + '\\' + tmp
            print('正在分析文件: ', file)
            data = getFields(file)
            token(tmp, data)

        files_black = os.listdir(black_path)
        for tmp2 in files_black:    #统计黑样本的词频
            file = black_path + '\\' + tmp2
            print('正在分析文件: ', file)
            data = getFields(file)
            token(tmp2, data)

        X = pd.read_csv(csv_path)
        X = X.drop(['file'], axis=1)

    Y = []

    for i in os.listdir(white_path):
        Y.append(0)
    for i in os.listdir(black_path):
        Y.append(1)

    classify(X, Y)

