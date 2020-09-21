#coding=utf-8

'''
通过判断语句:  if domain in alexas
过滤掉Alexa top1m的域名

读取子域名数量文件，建立域名：子域数量字典
查询第一步剩下的域名的子域数量
过滤掉子域名数量大于等于3的域名

计算香农熵，取前一百个熵值最大的域名
最后结果写入DGA_100.txt
'''

import xlrd


def filter(domain_file, alexa_file):
    """
    :param domain_file: 域名样本文件
    :param alexa_file: Alexa Top 1M 域名文件
    :return: malicious

    """

    '''
    --------    过滤掉Alexa域名    ---------
    '''
    alexas = []
    domains = []
    malicious = []
    first_split = []

    with open(domain_file, 'r') as f1:      #读取样本1域名
        domain_data = f1.readlines()
    for domain in domain_data:
        domains.append(domain.strip())
    # print(domains)

    with open(alexa_file, 'r') as f2:       #读取Alexa域名
        alexa_data = f2.readlines()
    for top_domain in alexa_data:
        alexas.append(top_domain.strip())
    # print(alexas)

    for domain in domains:
        if domain not in alexas:
            first_split.append(domain)

    print('first step malicious: ', first_split)
    print('-------------------')

    '''
    --------    过滤掉多子域域名    ---------
    '''

    sub_domain_dict = {}
    sub_domain_count_file = r'C:\Users\Administrator\Desktop\DNS恶意域名检测\2020Datacon.dns恶意域名\dns_2_question\子域名数量统计_3.xlsx'
    table = xlrd.open_workbook(sub_domain_count_file)
    sheet = table.sheet_by_index(0)
    # domains = []
    nrows = sheet.get_rows()
    for row in nrows:       #建立domain:subdomain_count字典
        if row[0].value != 'domain':
            sub_domain_dict[row[0].value] = row[1].value
    print(sub_domain_dict)
    print('-------------------')
    for domain in first_split:          #去除第一步结果中存在多个子域的域名
        if sub_domain_dict[domain] < 3:
            malicious.append(domain)

    print('Final malicious: ', malicious)
    print('-------------------')
    return malicious

# def shannon(word):
#     entropy = 0.0
#     length = len(word)
#     occ = {}
#     for c in word :
#         if not c in occ:
#             occ[ c ] = 0
#         occ += 1
#
#     for (k,v) in occ.iteritems():
#         p = float(v) / float(length)
#         entropy -= p * math.log(p, 2) # Log base 2
#         return entropy, word



def main():
    domain_file = r'C:\Users\Administrator\Desktop\DNS恶意域名检测\2020Datacon.dns恶意域名\dns_2_question\domains_3.txt'
    alexa_file = r'C:\Users\Administrator\Desktop\DNS恶意域名检测\top-1m.txt'
    w_file = r'C:\Users\Administrator\Desktop\DNS恶意域名检测\2020Datacon.dns恶意域名\dns_2_question\malicious_domains_3.txt'

    malicious = filter(domain_file, alexa_file)
    for domain in malicious:
        with open(w_file, 'a') as f:
            f.write(domain + '\n')
    entropys = []
    domains = []


    # for domain in malicious:
    #     entropy, domain = shannon(domain)
    #     entropys.append(entropy)
    #     domains.append(domain)
    #
    #     with open(w_file, 'a') as f5:






if __name__ == '__main__':
    main()