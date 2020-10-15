#coding=utf-8

'''
读取文件夹内所有的数据包文件名，加入列表
对列表进行循环：
    以文件名作为变量，统计（包长，方向）出现的次数，
    除以总报文数得到离散概率分布

Prob1:维数过大，csv单元格存储不完整，考虑不再写（长度，方向），直接写入频次/总报文数的汇总列表

'''

import os
import json
import csv
from concurrent.futures import ProcessPoolExecutor
import globalValue


def packet_feature(file):
    packet_dic = {}
    path = globalValue.global_path
    output = globalValue.global_feature_file
    cmd = 'tshark -T json -r %s -e frame.len -e ip.src -e ip.dst'
    host = file[:-5]    #获取主机ip地址
    absolute_path = path + file

    cmd = cmd % absolute_path
    # print('cmd: ', cmd)
    res = os.popen(cmd)     #调用系统命令
    data = str(res.read())  #获取终端命令执行结果
    json_data2 = json.loads(data)   #将字符串序列化为json格式
    count = 0   #统计报文数
    probability = {}    #存储离散概率字典
    for i in range(1515):
        probability[(i, 0)] = 0
        probability[(i, 1)] = 0
    # print(probability)
    for dic in json_data2:  #遍历packet包
        count += 1
        layers = dic.get("_source").get("layers")
        frame_len = int(layers.get("frame.len")[0])    #取到frame.len
        ip_src = layers.get("ip.src")[0]          #取到ip.src
        # ip_dst = layers.get("ip.dst")[0]          #取到ip.dst
        # print('frame len: ', frame_len, 'ip src: ', ip_src)
        if ip_src == host:  #判断报文方向
            io = 0
        else:
            io = 1
        # print('file: ', file, 'len: ', frame_len, 'src: ', ip_src, 'dst: ', ip_dst, 'io: ', io)
        item = (frame_len, io)
        probability[item] += 1
        # print('count: ', probability[item])
    # print('count: ', count, 'prob: ', probability)
    for key, value in probability.items():
        probability[key] = value / count    #计算离散概率
        # print('probability[{}]: {}'.format(key, probability[key]))

    discrete_probability = []
    discrete_probability.append(ip_src)
    discrete_probability.append('black')
    for value in probability.values():
        discrete_probability.append(value)
    print('discrete_probability: ', discrete_probability)
    with open(output, 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(discrete_probability)


    '''
    写入离散概率特征统计文件
    一个样本一个特征，特征最大为 1514x2 维
    '''
    packet_dic[host] = probability
    # print('正在处理：', host)
    # pd_data = [(ip_addr, feature) for ip_addr, feature in packet_dic.items()]
    pd_data = [feature for feature in packet_dic.values()]
    # print(pd_data)
    # with open(output, 'a', newline='') as f:
    #     writer = csv.writer(f)
    #     for row in pd_data:
    #         writer.writerow(row)
    # print('写入完毕，保存至：', output)




if __name__ == '__main__':
    files = os.listdir(globalValue.global_path)
    # print('文件夹内存在的数据包：', files)
    executor = ProcessPoolExecutor(max_workers=5)
    executor.map(packet_feature, files)