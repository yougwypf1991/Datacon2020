#coding=utf-8


from collections import Counter
import xlwt
from math import log

"""
提取特征包括：
            1.元音字母个数所占比例
            2.数字个数所占比例
            3.包含不同字母个数所占比例
            4.包含不同字母的个数
            5.信息熵
            6.重复字母个数所占比例
            7.连续辅音字母所占比例
            8.最小字符与最大字符的ASCII差值
            9.是否包含数字
"""

def vowel_ratio(domain, lenth):    #元音字母个数所占比例
    tmp = 0.0
    vowels = ['a', 'e', 'i', 'o', 'u']
    for alpha in domain:
        if alpha in vowels:
            tmp += 1.0
    ratio = tmp / lenth
    return ratio

def digital_ratio(domain, lenth):  #数字个数所占比例
    tmp = 0.0
    for alpha in domain:
        if alpha.isdigit():
            tmp += 1.0
    ratio = tmp / lenth
    return ratio

def char_diversity(domain, lenth): #包含不同字母个数所占比例
    tmp = 0.0
    alphas = []
    for alpha in domain:
        if alpha not in alphas and alpha.isalpha():
            alphas.append(alpha)
            tmp += 1.0
    ratio = tmp / lenth
    return ratio

def unialpha_ratio(domain): #包含不同字母的个数
    tmp = 0.0
    alphas = []
    for alpha in domain:
        if alpha not in alphas and alpha.isalpha():
            alphas.append(alpha)
            tmp += 1.0
    return tmp



def shannon_entropy(domain, lenth):   #计算信息熵
    numEntires = lenth
    labelCounts = {}
    for featVec in domain:
        currentLabel = featVec[-1]
        if currentLabel not in labelCounts.keys():
            labelCounts[currentLabel] = 0
        labelCounts[currentLabel] += 1
    shannonEnt = 0.0
    for key in labelCounts:
        prob = float(labelCounts[key]) / numEntires
        shannonEnt -= prob * log(prob, 2)
    return shannonEnt

def ratio_of_repeated_chars(domain, lenth):  #重复字母个数所占比例
    alphas = []
    sum = 0.0
    for alpha in domain:
        alphas.append(alpha)
    count = Counter(alphas)
    for key,value in count.items():
        if value > 1:
            sum += value
    print(count)
    print(sum)
    ratio = sum / lenth
    return ratio

def consecutive_consonant_ration(domain, lenth): #连续辅音字母所占比例
    tmp = 0.0
    maxConsec = 0.0
    vowels = ['a', 'e', 'i', 'o', 'u']
    for alpha in domain:
        if alpha not in vowels and alpha.isalpha():
            tmp += 1.0
            if tmp > maxConsec: maxConsec = tmp
        else:
            tmp = 0.0
    ratio = maxConsec / lenth
    return ratio

def start2end_asc(domain):    #最小字符与最大字符的ASCII差值
    domain = domain.strip()
    minAsc, maxAsc = 122.0, 0.0
    for alpha in domain:
        print('alpha: {}, asc: {}'.format(alpha, ord(alpha)))
        if ord(alpha) > maxAsc:
            maxAsc = ord(alpha)
        if ord(alpha) < minAsc:
            minAsc = ord(alpha)
    return maxAsc - minAsc

def contains_digital(domain): #是否包含数字
    for alpha in domain:
        if alpha.isdigit():
            return 1
        else:
            return 0

def main(file):     #返回提取的特征数据


    table = xlwt.Workbook(encoding='utf-8')
    sheet = table.add_sheet('feature_data')
    sheet.write(0, 0, label='元音字母所占比例')
    sheet.write(0, 1, label='数字个数所占比例')
    sheet.write(0, 2, label='不同字母个数所占比例')
    sheet.write(0, 3, label='包含不同字母的个数')
    sheet.write(0, 4, label='信息熵')
    sheet.write(0, 5, label='重复字母个数所占比例')
    sheet.write(0, 6, label='连续辅音字母所占比例')
    sheet.write(0, 7, label='ASC码差值')
    sheet.write(0, 8, label='是否包含数字')

    with open(file, 'r') as file:
        domains = file.readlines()
    tmp = 1
    for domain in domains:
        domain = domain[:-5]
        lenth = len(domain)

        vowel = vowel_ratio(domain, lenth)
        digital = digital_ratio(domain, lenth)
        char_div = char_diversity(domain, lenth)
        uni = unialpha_ratio(domain)
        shannon = shannon_entropy(domain, lenth)
        repeated = ratio_of_repeated_chars(domain, lenth)
        consonant = consecutive_consonant_ration(domain, lenth)
        sta2end = start2end_asc(domain)
        contain_dig = contains_digital(domain)

        sheet.write(tmp, 0, label=vowel)
        sheet.write(tmp, 1, label=digital)
        sheet.write(tmp, 2, label=char_div)
        sheet.write(tmp, 3, label=uni)
        sheet.write(tmp, 4, label=shannon)
        sheet.write(tmp, 5, label=repeated)
        sheet.write(tmp, 6, label=consonant)
        sheet.write(tmp, 7, label=sta2end)
        sheet.write(tmp, 8, label=contain_dig)

        tmp += 1
    table.save(r'C:\Users\Administrator\Desktop\DNS恶意域名检测\2020Datacon.dns恶意域名\dns_2_question\feature_data.xlsx')


if __name__ == '__main__':
    malicous_domains = r'C:\Users\Administrator\Desktop\DNS恶意域名检测\2020Datacon.dns恶意域名\dns_2_question\malicious.txt'
    main(malicous_domains)