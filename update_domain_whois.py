#!/usr/bin/python
# encoding:utf-8
"""
得到白名單中域名的whois的信息
使用了gevent多線程，加快訪問速度，目前線程爲10

"""
import re
import gevent
from gevent import socket
from random import choice
from tld import get_tld
from urlparse import urlparse
from top_whois_server_config import TLDs  # 获得顶级域名域名WHOIS服务器列表
from sql_command import Database
from whois_server_manage import *

"""
package:
    tld: 处理网址域名
    gevent: 多线程
"""

THREADNUM = 5


class domain_info:

    """
    域名whois信息类，包括网址域名、WHOIS服务器，WHOIS信息等内容
    """

    def __init__(self, url=''):

        self.url = url
        self.domain = ''
        self.top_whois_server = ''  # 顶级WHOIS服务器
        self.sec_whois_server = ''  # 二级WHOIS服务器
        self.real_sec_whois_server = ''  # 真实查询WHOIS服务器
        self.reg_name = ''   # 注册姓名
        self.reg_phone = ''  # 注册电话
        self.reg_email = ''  # 注册邮箱
        self.detail = ''     # detail

        self.achieve_top_whois_server()         # 获得顶级WHOIS服务器

    def achieve_top_whois_server(self):
        """
        根据顶级域名WHOIS信息注册商列表，获得顶级WHOIS服务器
        Args:
            url: 待查询的网址url
        Return: 
            domain, 网址域名
            top_whois_server, 域名的WHOIS顶级注册商
        Exception：
            1、tld中没有网址的顶级域名，返回空
            2、TLDs中没有域名的WHOIS注册商，返回空
        """

        url = self.url
        scheme = re.compile("https?\:\/\/", re.IGNORECASE) # 添加http头部
        if scheme.match(url) is None:
            url = "http://" + url
        try:
            res = get_tld(url, as_object=True)
            self.domain = res.tld
            domain_suffix = '.' + res.suffix
            top_whois_server = TLDs.get(domain_suffix, '')
            if top_whois_server:
                self.top_whois_server = top_whois_server
            else:
                print 'TLDs字典中没有该顶级域名WHOIS注册商，请联系管理员'
                return
        except:
            print 'tld没有该域名注册商，请联系管理员'
            return 

    def domain_whois(self):
        """
        获取域名注册商返回信息
        """
        data_result = ''

        if str(self.top_whois_server) == "['whois.verisign-grs.com', 'whois.crsnic.net']":  # 1.com,2.net

            data_result = self.get_socket('top')

            if not data_result:       #若为空则返回，结束
                print '顶级域名WHOIS查询结果为空'
                return
            domain_info = general_manage(data_result)   #顶级WHOIS包含注册信息，则查询结果返回，否则继续
            sec_whois_server = get_sec_server(data_result, self.domain) #二级查询，有结果则返回，没有则继续
            xxx_info = xxx_manage(data_result)                #xxx标志
            nomatch = no_match(data_result)
            if domain_info:
                self.update(domain_info)
                return
            elif sec_whois_server:
                self.sec_whois_server = sec_whois_server
                data_result = self.get_socket('second')
                if data_result:                                #到该层后则程序到此停止往下进行
                    domain_info = general_manage(data_result)
                    if domain_info:
                        self.update(domain_info)
                    else:
                        self.detail = data_result
                return
            elif xxx_info:
                data_result = self.get_socket('top', False)
                sec_whois_server = get_sec_server(data_result, self.domain)
                if sec_whois_server:
                    self.sec_whois_server = sec_whois_server
                    data_result = self.get_socket('second')
                    if data_result:
                        domain_info = general_manage(data_result)
                        if domain_info:
                            self.update(domain_info)
                        else:
                            self.detail = data_result
                return
            elif nomatch:
                self.update(nomatch)
                return
            return

        elif str(self.top_whois_server) == "['whois.nic.me', 'whois.meregistry.net']":
            data_result = self.get_socket('top')
            if not data_result:
                print '没有数据返回'
                return
            domain_info = general_manage(data_result)
            if domain_info:
                self.update(domain_info)
        # ua
        elif str(self.top_whois_server) == "whois.ua":
            self.query_domain = self.domain
            data_result = self.get_socket('top')
            if data_result:
                domain_info = ua_manage(data_result)
                self.update(domain_info)
        # ie
        elif str(self.top_whois_server) == "['whois.iedr.ie', 'whois.domainregistry.ie']":
            data_result = self.get_socket('top')
            if data_result:
                domain_info = ie_manage(data_result)
                self.update(domain_info)
        # es
        elif str(self.top_whois_server) == "whois.nic.es":
            data_result = self.get_socket('top')
            if data_result:
                domain_info = es_manage(data_result)
                self.update(domain_info)
        # ru
        elif str(self.top_whois_server) == "['whois.ripn.ru', 'whois.ripn.net']":
            data_result = self.get_socket('top')
            if data_result:
                domain_info = ru_manage(data_result)
                self.update(domain_info)
        # us,info,org
        elif (str(self.top_whois_server) == "['whois.pir.org', 'whois.publicinterestregistry.net']") or \
             (str(self.top_whois_server) == "whois.nic.us") or (str(self.top_whois_server) == "['whois.afilias.info', 'whois.afilias.net']"):
            data_result = self.get_socket('top')
            # print data_result
            if not data_result:
                print '没有数据返回'
                return
            domain_info = general_manage(data_result)
            if domain_info:
                self.update(domain_info)
        # to,tc
        elif (str(self.top_whois_server) == "whois.tonic.to") or (str(self.top_whois_server) == "whois.nic.es") or \
                (str(self.top_whois_server) == 'whois.eu') or (str(self.top_whois_server) == "whois.nic.tr") or \
                (str(self.top_whois_server) == "['whois.srs.net.nz', 'whois.domainz.net.nz']") or str(self.top_whois_server) == "whois.denic.de":
            data_result = self.get_socket('top')

            if data_result:
                domain_info = nomatch_manage(data_result)
                self.update(domain_info)
        # co_za
        elif str(self.top_whois_server) == "whois.registry.net.za":

            data_result = self.get_socket('top')

            if data_result:

                domain_info = co_za_manage(data_result)
                self.update(domain_info)

        elif str(self.top_whois_server) == "whois.audns.net.au":
            self.query_domain = self.domain
            data_result = self.get_socket('top')
            if data_result:

                domain_info = au_manage(data_result)
                self.update(domain_info)
        elif str(self.top_whois_server) == "whois.nic.cl":
            self.query_domain = self.domain
            data_result = self.get_socket('top')
            if data_result:
                domain_info = cl_manage(data_result)
                self.update(domain_info)
        elif str(self.top_whois_server) == "whois.nic.br":
            self.query_domain = self.domain
            data_result = self.get_socket('top')
            # print data_result
            if data_result:
                domain_info = nomatch_manage(data_result)
                self.update(domain_info)

        #biz ,mobi
        elif (str(self.top_whois_server) == "whois.dotmobiregistry.net") or (str(self.top_whois_server) == "whois.neulevel.biz") or \
             (str(self.top_whois_server) == 'whois.nic.xyz'):

            data_result = self.get_socket('top')
            if not data_result:
                print '没有数据返回'
                return
            domain_info = general_manage(data_result)
            if domain_info:
                self.update(domain_info)

        elif str(self.top_whois_server) == "whois.amnic.net":

            data_result = self.get_socket('top')
            # print data_result
            if data_result:
                domain_info = am_manage(data_result)
                self.update(domain_info)
        # as
        elif str(self.top_whois_server) == "whois.nic.as":
            data_result = self.get_socket('top')
            # print data_result
            if data_result:
                domain_info = as_manage(data_result)
                self.update(domain_info)
        elif str(self.top_whois_server) == "whois.adamsnames.tc" or str(self.top_whois_server) == "['whois.registrypro.pro', 'whois.registry.pro']" or \
                str(self.top_whois_server) == "['whois.inregistry.net', 'whois.registry.in']":
            data_result = self.get_socket('top')
            # print data_result
            if not data_result:
                print '没有数据返回'
                return
            domain_info = general_manage(data_result)
            if domain_info:
                self.update(domain_info)
        # cn
        elif str(self.top_whois_server) == "['whois.cnnic.cn', 'whois.cnnic.net.cn']":
            data_result = self.get_socket('top')
            # print data_result
            if data_result:
                domain_info = cn_manage(data_result)
                self.update(domain_info)
        # it
        elif str(self.top_whois_server) == "whois.nic.it":
            data_result = self.get_socket('top')
            # print data_result
            if data_result:
                domain_info = it_manage(data_result)
                self.update(domain_info)
        # pl
        elif str(self.top_whois_server) == "whois.dns.pl":
            data_result = self.get_socket('top')
            # print data_result
            if data_result:
                domain_info = pl_manage(data_result)
                self.update(domain_info)
        elif str(self.top_whois_server) == "whois.cira.ca":
            data_result = self.get_socket('top')
            # print data_result
            if data_result:
                domain_info = ca_manage(data_result)
                self.update(domain_info)

        # ae
        elif str(self.top_whois_server) == "whois.aeda.net.ae":
            data_result = self.get_socket('top')
            # print data_result
            if data_result:
                domain_info = ae_manage(data_result)
                self.update(domain_info)
        # ro
        elif str(self.top_whois_server) == "whois.rotld.ro":
            data_result = self.get_socket('top')
            # print data_result
            if data_result:
                domain_info = ro_manage(data_result)
                self.update(domain_info)
        # tw
        elif str(self.top_whois_server) == "whois.twnic.net.tw":
            self.query_domain = self.domain
            data_result = self.get_socket('top')
            # print data_result
            if data_result:
                domain_info = tw_manage(data_result)
                self.update(domain_info)
        # uk
        elif str(self.top_whois_server) == 'whois.nic.uk':
            data_result = self.get_socket('top')
            # print data_result
            if data_result:
                domain_info = uk_manage(data_result)
                self.update(domain_info)

    def get_socket(self, level='', flag=True):
        """
        与域名WHOIS信息注册商进行连接查询,level表示顶级或者二级查询，flag表示是否需要添加"="标志
        Args:
            level: 查询WHOIS顶级注册商(top),还是二级注册商(second)
            flag: 是否需要在查询域名前增加标志位'='，True不添加，False为添加
        
        Returns:
            data_result: 返回在域名注册商查询所得到的结果
        
        Exception：
            1、socket错误，连接或发送造成错误
            异常则返回False
        """
        if flag:                        #判断是否需要包含标志位'='
            query_domain = self.domain  # 无flag

        else:
            query_domain = '=' + self.domain  # 有'='

        # 顶级、二级域名查询
        if level == 'top':
            if type(self.top_whois_server) == list:  # 若WHOIS注册商为列表，则随机选择一个
                HOST = choice(self.top_whois_server)
            else:
                HOST = self.top_whois_server
        elif level == 'second':
            HOST = self.sec_whois_server

        data_result = ''
        PORT = 43
        BUFSIZ = 1024
        ADDR = (HOST, PORT)
        EOF = "\r\n"
        data_send = query_domain + EOF
        try:
            tcpCliSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tcpCliSock.connect(ADDR)
            tcpCliSock.send(data_send)
        except:
            print 'Socket Wrong'
            tcpCliSock.close()
            return False
        
        while True:
            try:
                data_rcv = tcpCliSock.recv(BUFSIZ)
            except:
                print 'Receive Failed'
                tcpCliSock.close()
                return False
            if not len(data_rcv):
                tcpCliSock.close()
                # print data_result
                return data_result  # 返回查询结果
            data_result = data_result + data_rcv

    def update(self, domain_info):

        self.reg_name = domain_info.get('reg_name', '')
        self.reg_email = domain_info.get('reg_email', '')
        self.reg_phone = domain_info.get('reg_phone', '')
        self.detail = domain_info.get('detail', '')
        print self.domain,self.reg_name,self.reg_email,self.reg_phone


def get_domain():

    try:
        db = Database()
        sql = "SELECT domain FROM domain_white_list_whois_copy WHERE (reg_email = '' AND reg_phone ='' AND reg_name = '' AND details = '')"
        domain = db.select_domain(sql)
        domain_list = [i[0] for i in domain]
        return domain_list
    except:
        print '获得查询域名异常'
        sys.exit(1)
    finally:
        db.close_db()


def check_domain(url=''):
    """
    查询域名WHOIS信息主程序
    """
    print url
    query_domain = ''
    query_domain = domain_info(url)
    if query_domain.domain and query_domain.top_whois_server: #根据是否有域名和域名WHOIS注册商条件判断
        query_domain.domain_whois()
        return query_domain
    else:
        return False


def main():

    domain_list = []
    domain_list = get_domain()
    total_domain_count = len(domain_list)
    print total_domain_count
    count = 0
    while count * THREADNUM < total_domain_count:
        domains = []
        db = Database()
        domains = domain_list[count * THREADNUM: (count + 1) * THREADNUM]
        jobs = [gevent.spawn(check_domain, str(domain.strip())) for domain in domains]
        gevent.joinall(jobs, timeout=10)
        count = count + 1
        db.update_white_whois(jobs)
        db.close_db()

if __name__ == '__main__':

    main()
