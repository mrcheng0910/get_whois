#!/usr/bin/python
# encoding:utf-8
"""
该程序主要用来执行数据库操作，查询以及更新，其他程序调用
@author:程亚楠
@date:2015.3.31
@version1.0
"""
import MySQLdb


class Database:

    def __init__(self, host='172.26.253.3', user='root', passwd='platform', db='malicious_detect'):
        """
        数据库初始化
        """
        self.host = host
        self.user = user
        self.passwd = passwd
        self.db = db
        self.charset = 'utf8'

    def __get_connect(self):
        """
        执行连接数据库操作
        """
        if not self.db:
            raise(NameError, 'There is not db information')
        try:
            self.conn = MySQLdb.Connection(
                host=self.host, user=self.user, passwd=self.passwd, db=self.db, charset=self.charset)
        except:
            raise(NameError, 'Connect failure')
        cursor = self.conn.cursor()
        if not cursor:
            raise(NameError, "Connect failure")
        else:
            return cursor

    def close_db(self):

        self.conn.commit()
        self.conn.close()

    def insert_domain_white_list(self, domain_list=[]):

        cursor = self.__get_connect()
        sql = 'INSERT INTO domain_white_list (domain) VALUES(%s)'
        try:
            cursor.executemany(sql, tuple(domain_list))
        except:
            raise(NameError, 'update failure')

    def insert_white_whois(self, jobs):

        sql = "INSERT INTO  domain_white_list_whois_copy (domain,top_whois_server,sec_whois_server,\
               reg_name, reg_phone,reg_email,details) VALUES( %s,%s,%s,%s,%s,%s,%s)"
        cursor = self.__get_connect()
        for domain in jobs:
            query_domain = domain.value
            try:
                if query_domain:
                    cursor.execute(sql, (query_domain.domain, str(query_domain.top_whois_server),
                                         query_domain.sec_whois_server, query_domain.reg_name, query_domain.reg_phone, query_domain.reg_email,query_domain.detail))
                # print 'success'
            except:
                print 'Insert Wrong'
                continue

    def select_domain(self,sql=''):

        if sql:
            cursor = self.__get_connect()
            cursor.execute(sql)
            return cursor.fetchall()
        else:
            return

    def update_white_whois(self,jobs):
        sql = "UPDATE domain_white_list_whois_copy (top_whois_server,sec_whois_server,\
               reg_name, reg_phone,reg_email,details) VALUES( %s,%s,%s,%s,%s,%s) WHERE domain = %s"
        cursor = self.__get_connect()
        for domain in jobs:
            query_domain = domain.value
            try:
                if query_domain.domain:
                    cursor.execute(sql, (str(query_domain.top_whois_server),query_domain.sec_whois_server, query_domain.reg_name, \
                        query_domain.reg_phone, query_domain.reg_email,query_domain.detail,query_domain.domain))
            except:
                return
