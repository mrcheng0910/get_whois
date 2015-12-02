#!/usr/bin/python
# encoding:utf-8

import re
import sys
# from socket import *
from gevent import socket
# import socket
from urlparse import urlparse
from random import choice
reload(sys)
sys.setdefaultencoding( "utf-8" )

def get_socket(HOST='',domain=''):


    if type(HOST) == list: #If the server are lists,random choose one.
        HOST = choice(HOST)

    print HOST
    print domain

    PORT = 43
    BUFSIZ = 1024
    ADDR = (HOST, PORT)
    EOF = "\r\n"
    data_send = domain + EOF

    try:
        tcpCliSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcpCliSock.settimeout(15)
    except socket.error, msg:
        print 'Failed to create socket. Error code:' + str(msg[0]) + ', Error message:' + msg[1]
        # sys.exit()
        return
    try:
        tcpCliSock.connect(ADDR)
    except socket.error,e:
        print e
        # sys.exit()
        return
    try:

        tcpCliSock.send(data_send)
    except error,e:
        print e
        # sys.exit()
        return

    data_result = ''

    while True:
        
        try:
            data_rcv = tcpCliSock.recv(BUFSIZ)
        except socket.error,e:
            # print 'receive Failed'
            # print socket.error
            print e
            tcpCliSock.close()
            return

        if not len(data_rcv):
            print data_result
            tcpCliSock.close()
            return data_result
        data_result = data_result + str(data_rcv)
    tcpCliSock.close()

def sa_manage(data_result):

    domain_info = {}
    pattern = re.compile(r'(Name:.*|Email:.*|Phone.*)')
    match = pattern.findall(data_result)
    print match
    # print match[0].split('\t\t')
    count = len(match)
    for i in range(count):

        if match[i].split(':')[0].strip()=='Name':
            domain_info['reg_name'] = match[i].split(':')[1].strip()
        elif match[i].split(':')[0].strip()=='Phone':
            domain_info['reg_phone'] = match[i].split(':')[1].strip()
            break
        elif match[i].split(':')[0].strip()=='Email':
            domain_info['reg_email'] = match[i].split(':')[1].strip()
    print domain_info
    return domain_info
# def sa_manage(data_result):
#     i = 0
#     count = 0
#     domain_info = {}
#     pattern = re.compile(r'(holder-c:.*|nic-hdl:.*|contact:.*)')
#     match = pattern.findall(data_result)
#     # print match
#     count  = len(match)
#     for i in range(count):
#         if match[i].split(':')[0].strip() == 'holder-c':
#             holder = match[i].split(':')[1].strip()
#         if match[i].split(':')[0].strip()=='nic-hdl' and match[i].split(':')[1].strip()==holder:
#             try:
#                 domain_info['reg_name'] = match[i+1].split(':')[1].strip()
#                 break
#             except:
#                 pass

#     # print domain_info
#     return domain_info

def main():

    data_result = ''
    url = 'unread-help-msg.email'
    # url = 'origami.co''whois.registry.in']motors.msk.ru["whois.ripn.ru", "whois.ripn.net"],
    
    # data_result = get_socket("whois.nic.il",url)
    # data_result = get_socket("192.115.0.12",url)
    data_result=get_socket('whois.donuts.co',url)
    if data_result:
        sa_manage(data_result)


if __name__ == '__main__':
    main()