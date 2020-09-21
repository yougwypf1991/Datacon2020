#coding=utf-8

'''
通过正则表达式检测域名内是否存在可读字符串

完成字符串检测
TODO：从benigns.txt中筛出误判断的恶意域名
                            --2020.09.17

单词与拼音分开检测，单词只需出现一次，
拼音需出现两次以上才判定为良性域名

TODO: KMeans分类出不同家族域名
                            --2020.09.18

'''

import re

"""
Params:
        words：
"""

domains = []
benigns = []
malicious = []

word_file = r'C:\Users\Administrator\Desktop\DNS恶意域名检测\2020Datacon.dns恶意域名\dns_2_question\words.txt'
pinyin_file = r'C:\Users\Administrator\Desktop\DNS恶意域名检测\2020Datacon.dns恶意域名\dns_2_question\拼音.txt'
domains_file = r'C:\Users\Administrator\Desktop\DNS恶意域名检测\2020Datacon.dns恶意域名\dns_2_question\malicious_domains_3.txt'
malicious_file = r'C:\Users\Administrator\Desktop\DNS恶意域名检测\2020Datacon.dns恶意域名\dns_2_question\malicious.txt'
benigns_file = r'C:\Users\Administrator\Desktop\DNS恶意域名检测\2020Datacon.dns恶意域名\dns_2_question\benigns.txt'


with open(word_file, 'r') as f1:                #读取单词文件，建立匹配模型
    word_data = f1.read().replace('\n', '|')
print(word_data)

with open(pinyin_file, 'r') as f2:              #读取拼音文件，建立匹配模型
    pinyin_data = f2.read().replace('\n', '|')
print(pinyin_data)

word_model = re.compile(word_data)

pinyin_data = '(' + pinyin_data + '){2}'
print('pinyin data: ', pinyin_data)
pinyin_model = re.compile('(' + pinyin_data + '){2,}')  #拼音匹配两次及以上


with open(domains_file, 'r') as f3:     #读取域名文件
    domain_data = f3.readlines()
for domain in domain_data:
    domains.append(domain.rstrip())


for domain in domains:      #判断域名内是否存在英文单词或2个及以上的拼音
    if (word_model.search(domain) or pinyin_model.search(domain)):
        benigns.append(domain)
        print('良性域名', domain)
        if word_model.search(domain):
            print('匹配到单词', word_model.search(domain))
        elif pinyin_model.search(domain):
            print('匹配到拼音', pinyin_model.search(domain))
        print('--------------')
    else:
        malicious.append(domain)
        print('恶意域名', domain)
        print('--------------')

# for domain in domains:
#     if word_model.search(domain):
#         print('匹配到单词: ',word_model.search(domain), '域名：', domain )


for domain in domains:
    with open(malicious_file, 'a') as f1:
        f1.write(domain + '\n')

for domain in benigns:
    with open(benigns_file, 'a') as f2:
        f2.write(domain + '\n')