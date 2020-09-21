#coding=utf-8
'''
从chaziyu.com查询子域名数量
以 domain sub_domain_count 形式写入 子域名数量统计.xlsx 文件

'''
import requests
from bs4 import BeautifulSoup
from fake_useragent import UserAgent
import xlwt
import time

def main(url, domains, counts):     #将域名与子域名数量对应保存至'子域名数量统计.xlsx'文件
    book = xlwt.Workbook(encoding='utf-8', style_compression=0)         #创建Excel文件
    sheet = book.add_sheet('各域名子域名数量', cell_overwrite_ok=True)  #添加子表
    sheet.write(0, 0, 'domain')
    sheet.write(0, 1, 'subdomain count')

    tmp = 1
    for domain in domains:
        html = request_domain(url, domain)
        if html:                                        #网页解析异常时按照0子域处理
            soup = BeautifulSoup(html, 'lxml')
            count = save_sub_count(soup)
            counts.append(count)
            sheet.write(tmp, 0, domain)
            sheet.write(tmp, 1, counts[tmp - 1])
        else:
            counts.append(0)
            sheet.write(tmp, 0, domain)
            sheet.write(tmp, 1, counts[tmp - 1])

        tmp += 1
        time.sleep(1)
    print(counts)
    book.save(r'C:\Users\Administrator\Desktop\DNS恶意域名检测\2020Datacon.dns恶意域名\dns_2_question\子域名数量统计_3.xlsx')



def request_domain(url, domain):    #请求子域名查询页面
    user_agent = UserAgent()
    agent = user_agent.random
    headers = {
        "User-Agent": agent
    }
    query_url = url + domain
    try:
        print('开始请求：', query_url)
        print('-----------------')
        res = requests.get(query_url, headers=headers)
        if res.status_code == 200:
            return res.content.decode('utf-8')
    except Exception:
        print('请求错误：', url)
        return None

def save_sub_count(soup):   #解析子域名数量
    try:
        print('开始解析')
        print('-------------')
        lists = soup.find_all(class_="J_link")
        print('子域名数量：', len(lists))
        return len(lists)
    except Exception:
        print('页面解析错误！')
        print('--------------')

if __name__ == '__main__':  #url, domains, counts
    url = 'https://chaziyu.com/'
    domains = []
    counts = []

    r_file = r'C:\Users\Administrator\Desktop\DNS恶意域名检测\2020Datacon.dns恶意域名\dns_2_question\domains_3.txt'
    # r_file = r_file + str(i) + '.txt'
    with open(r_file, 'r') as file:
        split_domain = file.readlines()
    for domain in split_domain:
        domains.append(domain.rstrip())
    print('All domains: ', domains)
    print('------------------')

    main(url, domains, counts)