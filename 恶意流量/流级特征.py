#coding=utf-8

import os
import numpy as np
import pandas as pd
import global_path
from sklearn.naive_bayes import BernoulliNB
from sklearn.model_selection import train_test_split

'''
完成流级特征分类功能
def tcp_tuple 提取tcp四元组数据并写入tuple.csv文件

'''

def tcp_tuple(path):
    '''
    指定tshark -r file.pcap -q -z conv,tcp命令，得到tcp四元组的统计信息
    处理命令返回结果的字符串，去掉不需要的内容
    将字符串分割为符合csv文件的格式，写入DataFrame
    最后统一输入csv
    :param path: 存储用于训练的pcap文件的文件夹
    :return DataFrame: 四元组数据组成的DataFrame句柄
    '''
    files = os.listdir(path)
    cmd = 'tshark -r {pcap} -q -z conv,tcp'
    # headers = [['ip.src', 'ip.dst', 'in_packets', 'in_bytes', 'out_packets', 'out_bytes', 'duration']]
    headers = [['ip.src', 'ip.dst', 'in_packets', 'in_bytes', 'out_packets', 'out_bytes', 'duration']]

    sum_df = pd.DataFrame(headers)

    '''
    获取所有pcap文件内的四元组数据
    '''
    for file in files:
        pcap = path + '\\' + file
        data = os.popen(cmd.format(pcap=pcap)).read()   #获取命令执行结果
        data = np.array(data.split('|')[-1].split('=')[0].split())  #切割出需要的数据内容
        df = pd.DataFrame(data.reshape(-1, 11)) #重新排列，转为csv格式
        df = df.drop([1, 7, 8, 9], axis=1)  #筛除无用数据
        df = df.T.reset_index(drop=True).T  #重置列索引
        sum_df = pd.concat([sum_df, df])    #拼接进总的DataFrame
        print(file, ' 提取完毕')

    return sum_df


def tuple_csv(DataFrame, path):
    '''
    将数据打上类别标签，写入csv文件
    :param DataFrame: path路径下所有的pcap文件中提取出来的tcp流元组数据
    :return:
    '''
    label_white = ['label']
    label_black = ['label']

    if path == global_path.white_path:
        for i in range(DataFrame.shape[0] -1):
            label_white.append('0')
        DataFrame['7'] = label_white
    elif path == global_path.black_path:
        for i in range(DataFrame.shape[0] -1):
            label_black.append('1')
        DataFrame['7'] = label_black

    DataFrame = DataFrame.drop([0], axis=0)
    DataFrame.columns = ['ip.src', 'ip.dst', 'in_packets', 'in_bytes', 'out_packets', 'out_bytes', 'duration', 'label']
    print(DataFrame)
    if os.path.exists(tuple_data_path):
        DataFrame.to_csv(tuple_data_path, index=False, header=False, mode='a')
    else:
        DataFrame.to_csv(tuple_data_path, index=False)


def classify(DataFrame):
    '''
    读取DataFrame，训练贝叶斯分类器
    预测测试数据类型
    :param DataFrame: 所有pcap文件中提取出来的tcp流元组数据
    :return:
    '''
    X = DataFrame[['in_packets', 'in_bytes', 'out_packets', 'out_bytes', 'duration']]
    Y = DataFrame['label']
    X_train, X_test, Y_train, Y_test = train_test_split(X, Y, random_state=11, test_size=0.1)

    alphas = np.logspace(-5, 10, num=30)
    binarizes=np.linspace(-10, 20, endpoint=True, num=60)

    highest = 0
    cls = BernoulliNB()

    for alpha in alphas:
        for binarize in binarizes:
            cls = BernoulliNB(alpha=alpha)
            cls.fit(X_train, Y_train)
            train_score = cls.score(X_train, Y_train)
            test_score = cls.score(X_test, Y_test)

            if test_score > highest:
                highest = test_score
                print('当前最高训练分数: ', train_score)
                print('当前最高测试分数: ', test_score)
                print('参数值 alpha:', alpha, 'binarize:',binarize)

if __name__ == '__main__':
    tuple_data_path = global_path.csv_path + '\\tuple.csv'
    if not os.path.exists(tuple_data_path):     #若tuple.csv文件不存在，需要读取pcap文件，建立训练数据集
        white_df = tcp_tuple(global_path.white_path)
        tuple_csv(white_df, global_path.white_path)

        black_df = tcp_tuple(global_path.black_path)
        tuple_csv(black_df, global_path.black_path)

    df = pd.read_csv(tuple_data_path)
    print('train df:\n', df)
    classify(df)