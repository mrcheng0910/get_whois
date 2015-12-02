# encoding:utf-8

import sys
import re
import os

def general_manage(data_result):
    domain_info = {}
    i = 0
    pattern = re.compile(
        r'(Registrant Phone:.*|Registrant Name:.*|Registrant Email:.*|Registrant E-mail:.*|Registrant Phone Number:.*)')
    match = pattern.findall(data_result)
    # print match
    match_length = len(match)
    if match:
        for i in range(match_length):
            if match[i].split(':')[0].strip() == 'Registrant Phone':
                domain_info['reg_phone'] = match[i].split(':')[1].strip()
            elif match[i].split(':')[0].strip() == 'Registrant Name':
                domain_info['reg_name'] = match[i].split(':')[1].strip()
            elif match[i].split(':')[0].strip() == 'Registrant Email':
                domain_info['reg_email'] = match[i].split(':')[1].strip()
            elif match[i].split(':')[0].strip() == 'Registrant E-mail':
                domain_info['reg_email'] = match[i].split(':')[1].strip()
            elif match[i].split(':')[0].strip() == 'Registrant Phone Number':
                domain_info['reg_phone'] = match[i].split(':')[1].strip()

    domain_info['detail'] = str(data_result)
    return domain_info


def get_sec_server(data_result, query_domain):

    pattern = re.compile(r'Domain Name:.*|Whois Server:.*|WHOIS Server:.*')
    match = pattern.findall(data_result)
    
    if match:
        # print match
        length = len(match)
        for i in range(length):
            # print match[i].lower()
            if match[i].lower().find(query_domain) != -1:

                try:
                    sec_whois_server = match[i+1].split(':')[1].strip()
                    # print sec_whois_server
                    return sec_whois_server
                except:
                    print 'Something Else Wrong'
                    return


def xxx_manage(data_result):

    pattern_other = re.compile(r'xxx')
    match_other = pattern_other.search(str(data_result))

    if match_other:
        return True
    else:
        return False


def no_match(data_result):
    domain_info = {}
    pattern_no = re.compile(r'No match')
    match = pattern_no.search(data_result)
    if match:
        print 'NoMatch'
        domain_info['reg_name'] = 'NoMatch'
    domain_info['detail'] = data_result
    return domain_info


def ua_manage(data_result):
    domain_info = {}

    domain_info['detail'] = str(data_result)
    return domain_info


def ie_manage(data_result):

    domain_info = {}
    pattern = re.compile(r'(person:.*)')
    match = pattern.findall(data_result)
    print match
    if match:
        domain_info['reg_name'] = match[0].split(':')[1].strip()
    domain_info['detail'] = str(data_result)
    return domain_info


def es_manage(data_result):
    domain_info = {}
    domain_info['detail'] = str(data_result)
    return domain_info


def ru_manage(data_result):

    domain_info = {}
    pattern = re.compile(r'(person:.*|registrar:.*)')
    match = pattern.findall(data_result)
    print match
    if match:
        domain_info['reg_name'] = match[0].split(':')[1].strip()
    domain_info['detail'] = data_result
    return domain_info


def nomatch_manage(data_result):
    domain_info = {}
    domain_info['detail'] = str(data_result)
    return domain_info


def co_za_manage(data_result):
    domain_info = {}
    pattern = re.compile(r'(Registrant:\s\s.*|Email:.*|Tel:.*)')
    match = pattern.findall(data_result)
    print match
    count = len(match)
    for i in range(count):

        if match[i].find('Registrant:') >= 0:
            domain_info['reg_name'] = match[i].split(':')[1].strip()
        elif match[i].find('+') >= 0:
            domain_info['reg_phone'] = match[i].split(':')[1].strip()
        elif match[i].find('@') >= 0:
            domain_info['reg_email'] = match[i].split(':')[1].strip()
    domain_info['detail'] = str(data_result)
    return domain_info


def au_manage(data_result):

    domain_info = {}
    pattern = re.compile(
        r'(Registrant Contact Name:.*|Registrant Contact Email:.*)')
    match = pattern.findall(data_result)
    print match
    count = len(match)

    for i in range(count):

        if match[i].split(':')[0].strip() == 'Registrant Contact Name':
            domain_info['reg_name'] = match[i].split(':')[1].strip()
        elif match[i].split(':')[0].strip() == 'Registrant Contact Email':
            domain_info['reg_email'] = match[i].split(':')[1].strip()
    domain_info['detail'] = str(data_result)
    return domain_info


def am_manage(data_result):

    domain_info = {}
    pattern = re.compile(r'(Administrative contact:\s\s.*|\+.*|.*@.*)')
    match = pattern.findall(data_result)
    print match
    count = len(match)

    for i in range(count):

        if match[i].find('Administrative contact:') >= 0:
            domain_info['reg_name'] = match[i].split(':')[1].strip()
        elif match[i].find('+') >= 0:
            domain_info['reg_phone'] = match[i].strip()
        elif match[i].find('@') >= 0:
            domain_info['reg_email'] = match[i].strip()
    domain_info['detail'] = str(data_result)
    return domain_info


def as_manage(data_result):

    domain_info = {}
    pattern = re.compile(r'(Registrar:\s\s.*)')
    match = pattern.findall(data_result)
    print match
    if match:
        domain_info['reg_name'] = match[0]
    domain_info['detail'] = data_result
    return domain_info


def cn_manage(data_result):
    domain_info = {}
    pattern = re.compile(
        r'(Registrant Phone Number:.*|Registrant:.*|Registrant Contact Email:.*)')
    match = pattern.findall(data_result)
    match_length = len(match)

    print match

    for i in range(match_length):
        if match[i].split(':')[0].strip() == 'Registrant Phone Number':
            domain_info['reg_phone'] = match[i].split(':')[1].strip()
        elif match[i].split(':')[0].strip() == 'Registrant':
            domain_info['reg_name'] = match[i].split(':')[1].strip()
        elif match[i].split(':')[0].strip() == 'Registrant Contact Email':
            domain_info['reg_email'] = match[i].split(':')[1].strip()
    domain_info['detail'] = str(data_result)
    return domain_info


def it_manage(data_result):
    domain_info = {}
    pattern = re.compile(r'(Name:.*)')
    match = pattern.findall(data_result)
    print match
    count = len(match)
    if match:
        domain_info['reg_name'] = match[0].split(':')[1].strip()
    domain_info['detail'] = str(data_result)
    return domain_info


def pl_manage(data_result):
    domain_info = {}
    pattern = re.compile(r'(REGISTRAR:\s\s.*|\+.*|.*@.*)')
    match = pattern.findall(data_result)
    print match
    count = len(match)

    for i in range(count):
        if match[i].find('REGISTRAR:') >= 0:
            domain_info['reg_name'] = match[i].split(':')[1].strip()
        elif match[i].find('+') >= 0:
            domain_info['reg_phone'] = match[i].strip()
        elif match[i].find('@') >= 0:
            domain_info['reg_email'] = match[i].strip()
    domain_info['detail'] = str(data_result)
    return domain_info


def ca_manage(data_result):
    domain_info = {}
    pattern = re.compile(r'Registrar:\n.+Name:(.*)')
    match = pattern.findall(data_result)
    count = len(match)
    if match:
        domain_info['reg_name'] = match[0].strip()
    domain_info['detail'] = str(data_result)
    return domain_info


def ae_manage(data_result):
    domain_info = {}
    pattern = re.compile(
        r'(Registrant Contact Name:.*|Registrant Contact Email:.*)')
    match = pattern.findall(data_result)
    print match
    count = len(match)

    for i in range(count):

        if match[i].split(':')[0].strip() == 'Registrant Contact Name':
            domain_info['reg_name'] = match[i].split(':')[1].strip()
        elif match[i].split(':')[0].strip() == 'Registrant Contact Email':
            domain_info['reg_email'] = match[i].split(':')[1].strip()
    domain_info['detail'] = str(data_result)
    return domain_info


def ro_manage(data_result):
    domain_info = {}
    pattern = re.compile(r'(Domain Name:.*|Registrar:.*)')
    match = pattern.findall(data_result)
    print match
    count = len(match)
    for i in range(count):
        if match[i].split(':')[0].strip() == 'Registrar':
            domain_info['reg_name'] = match[i].split(':')[1].strip()
    domain_info['detail'] = str(data_result)
    return domain_info


def tw_manage(data_result):

    domain_info = {}
    i = 0
    pattern = re.compile(r'(Registrant:\s.*|\+.*)')

    match = pattern.findall(data_result)
    print match
    count = len(match)

    for i in range(count):

        if match[i].split(':')[0].strip() == 'Registrant':

            domain_info['reg_name'] = match[i].split(':')[1].strip()
        elif match[i].find('+') >= 0:
            domain_info['reg_phone'] = match[i].strip()

    pattern_em = re.compile(r'(.*@.*)')
    match_em = pattern_em.findall(data_result)
    print match_em
    if match_em:
        domain_info['reg_email'] = str(match_em)
    print domain_info
    domain_info['detail'] = str(data_result)
    return domain_info


def uk_manage(data_result):
    domain_info = {}
    pattern = re.compile(r"(Registrant's address:\s\s.*\s\s.*)")
    match = pattern.findall(data_result)
    match_length = len(match)
    print match

    for i in range(match_length):
        if match[i].split(':')[0].strip() == "Registrant's address":
            domain_info['reg_name'] = match[i].split(
                ':')[1].strip().replace('\r\n      ', ' ')
    domain_info['detail'] = str(data_result)
    return domain_info


def cl_manage(data_result):
    domain_info = {}
    pattern = re.compile(r'(Nombre.*)')
    match = pattern.findall(data_result)
    print match
    if match:
        domain_info['reg_name'] = match[0].split(':')[1].strip()
    domain_info['detail'] = str(data_result)
    return domain_info


def kz_manage(data_result):

    domain_info = {}
    pattern = re.compile(r'Phone Number.*|Email Address.*|Name\..*')
    match = pattern.findall(data_result)
    count = len(match)
    print match
    for i in range(count):
        if match[i].split(':')[0].strip().find("Phone Number") >= 0:
            domain_info['reg_phone'] = match[i].split(':')[1].strip()
        elif match[i].split(':')[0].strip().find("Email Address") >= 0:
            domain_info['reg_email'] = match[i].split(':')[1].strip()
        elif match[i].split(':')[0].strip().find("Name") >= 0:
            domain_info['reg_name'] = match[i].split(':')[1].strip()

    domain_info['detail'] = data_result
    return domain_info


def nc_manage(data_result):

    domain_info = {}
    pattern = re.compile(r'Registrant name.*')
    match = pattern.findall(data_result)
    # count = len(match)
    print match
    if match:
        domain_info['reg_name'] = match[0].split(':')[1].strip()
    domain_info['detail'] = data_result
    return domain_info


def kr_manage(data_result):

    domain_info = {}
    i = 0
    pattern = re.compile(
        r'(AC Phone Number.*|Registrant.*|AC Email.*)')
    match = pattern.findall(data_result)
    match_length = len(match)
    if match:
        for i in range(match_length):
            if match[i].split(':')[0].strip() == 'AC Phone Number':
                domain_info['reg_phone'] = match[i].split(':')[1].strip()
            elif match[i].split(':')[0].strip() == 'Registrant':
                domain_info['reg_name'] = match[i].split(':')[1].strip()
            elif match[i].split(':')[0].strip() == 'AC Email':
                domain_info['reg_email'] = match[i].split(':')[1].strip()

    domain_info['detail'] = str(data_result)
    return domain_info


def mx_manage(data_result):
    domain_info = {}
    pattern = re.compile(r"(Registrant:\s\s.*)")
    match = pattern.findall(data_result)
    match_length = len(match)
    print match
    if match:
        domain_info['reg_name'] = match[0].split(':')[-1].strip()
    domain_info['detail'] = str(data_result)
    return domain_info


def rs_manage(data_result):

    domain_info = {}
    i = 0
    pattern = re.compile(
        r'(ID Number.*|Registrant:.*)')
    match = pattern.findall(data_result)
    match_length = len(match)
    if match:
        for i in range(match_length):
            if match[i].split(':')[0].strip() == 'ID Number':
                domain_info['reg_phone'] = match[i].split(':')[1].strip()
            elif match[i].split(':')[0].strip() == 'Registrant':
                domain_info['reg_name'] = match[i].split(':')[1].strip()

    domain_info['detail'] = str(data_result)
    return domain_info

def sg_manage(data_result):
    
    domain_info = {}
    pattern = re.compile(r"(Registrant:\s\s\s\s\s.*)")
    match = pattern.findall(data_result)
    match_length = len(match)
    print match
    if match:
        domain_info['reg_name'] = match[0].split(':')[-1].strip()
    domain_info['detail'] = str(data_result)
    return domain_info

def sa_manage(data_result):
    domain_info = {}
    i = 0
    pattern = re.compile(r'(Registrant:\s\s.*)')
    match = pattern.findall(data_result)
    match_length = len(match)
    print match
    if match:
        domain_info['reg_name'] = match[0].split(':')[1].strip() 
    
    domain_info['detail'] = str(data_result)
    # print domain_info
    return domain_info

def br_manage(data_result):

    domain_info = {}
    i = 0
    pattern = re.compile(r'(owner.*)')
    match = pattern.findall(data_result)
    match_length = len(match)
    print match
    if match:
        domain_info['reg_name'] = match[0].split(':')[1].strip() 
    
    domain_info['detail'] = str(data_result)
    # print domain_info
    return domain_info

def no_manage(data_result):
    print data_result
    domain_info = {}
    pattern = re.compile(
        r'([\n]Name\..*|Phone Number.*|Email Address.*)')
    match = pattern.findall(data_result)
    print match
    count = len(match)

    for i in range(count):

        if match[i].split(':')[0].strip().find('Name')>=0:
            domain_info['reg_name'] = str(match[i].split(':')[1].strip())
        elif match[i].split(':')[0].strip().find('Phone Number')>=0:
            domain_info['reg_phone'] = match[i].split(':')[1].strip()
        elif match[i].split(':')[0].strip().find('Email Address')>=0:
            domain_info['reg_email'] = match[i].split(':')[1].strip()

    domain_info['detail'] = str(data_result)

    return domain_info


def sn_manage(data_result):

    domain_info = {}
    pattern = re.compile(
        r'(Pays Registrant:.*|Telephone Registrant.*|Courriel Registrant.*)')
    match = pattern.findall(data_result)
    print match
    count = len(match)

    for i in range(count):

        if match[i].split(':')[0].strip()=='Pays Registrant':
            domain_info['reg_name'] = match[i].split(':')[1].strip()
        elif match[i].split(':')[0].strip()=='Telephone Registrant':
            domain_info['reg_phone'] = match[i].split(':')[1].strip()
        elif match[i].split(':')[0].strip()=='Courriel Registrant.':
            domain_info['reg_email'] = match[i].split(':')[1].strip()
    domain_info['detail'] = str(data_result)
    
    return domain_info

def jp_manage(domain):
    
    command = 'whois ' + domain
    result = os.popen(command)
    data_result = result.read()
    domain_info = {}
    pattern = re.compile(r'(\[Name\].*|\[Phone\].*|\[Email\].*|\[Administrative Contact\].*)')
    match = pattern.findall(data_result)
    # print match[0].split(']')
    # print match[0].split('')[2:]
    count = len(match)
    # print data_result
    for i in range(count):

        if match[i].split(' ')[0].strip()=='[Name]':
            domain_info['reg_name'] = match[i][6:].strip()
        elif match[i].split(' ')[0].strip()=='[Phone]':
            domain_info['reg_phone'] = match[i][7:].strip()
        elif match[i].split(' ')[0].strip()=='[Email]':
            domain_info['reg_email'] = match[i][7:].strip()
        elif match[i].split(']')[0].strip()=='[Administrative Contact':
            domain_info['reg_name'] = match[i][24:].strip()
    # domain_info['detail'] = str(data_result)
    # print domain_info
    
    return domain_info

def fm_manage(data_result):

    domain_info = {}
    pattern = re.compile(
        r'(Registrar Name:.*|Phone:.*|Customer Service Email:.*)')
    match = pattern.findall(data_result)
    print match
    count = len(match)

    for i in range(count):

        if match[i].split(':')[0].strip()=='Registrar Name':
            domain_info['reg_name'] = match[i].split(':')[1].strip()
        elif match[i].split(':')[0].strip()=='Phone':
            domain_info['reg_phone'] = match[i].split(':')[1].strip()
        elif match[i].split(':')[0].strip()=='Customer Service Email':
            domain_info['reg_email'] = match[i].split(':')[1].strip()
    print domain_info
    domain_info['detail'] = str(data_result)
    
    return domain_info

def io_manage(data_result):

    domain_info = {}
    pattern = re.compile(r'(Owner.*)')
    match = pattern.findall(data_result)
    print match
    count = len(match)
    if match:
        domain_info['reg_name'] = match[0].split(':')[1].strip()
    # print domain_info
    domain_info['detail'] = str(data_result)
    
    return domain_info

def ir_manage(data_result):
    i = 0
    count = 0
    domain_info = {}
    pattern = re.compile(r'(holder-c:.*|nic-hdl:.*|person:.*|e-mail:.*|phone:.*)')
    match = pattern.findall(data_result)
    # print match
    count  = len(match)
    for i in range(count):
        if match[i].split(':')[0].strip() == 'holder-c':
            holder = match[i].split(':')[1].strip()
        if match[i].split(':')[0].strip()=='nic-hdl' and match[i].split(':')[1].strip()==holder:
            try:
                domain_info['reg_name'] = match[i+1].split(':')[1].strip()
                domain_info['reg_email'] = match[i+2].split(':')[1].strip()
                domain_info['reg_phone'] = match[i+3].split(':')[1].strip()
                break
            except:
                pass

    # print domain_info
    return domain_info


def il_manage(data_result):

    holder = ''
    i = 0
    count = 0
    domain_info = {}
    pattern = re.compile(r'(admin-c:.*|nic-hdl:.*|person:.*|e-mail:.*|phone:.*)')
    match = pattern.findall(data_result)
    # print match
    count  = len(match)
    for i in range(count):
        if match[i].split(':')[0].strip() == 'admin-c':
            holder = match[i].split(':')[1].strip()
        if match[i].split(':')[0].strip()=='nic-hdl' and match[i].split(':')[1].strip()==holder:
            try:
                domain_info['reg_name'] = match[i-3].split(':')[1].strip()
                domain_info['reg_email'] = match[i-1].split(':')[1].strip()
                domain_info['reg_phone'] = match[i-2].split(':')[1].strip()
                break
            except:
                pass

    # print domain_info
    return domain_info

def im_manage(data_result):

    domain_info = {}
    pattern = re.compile(r'(Domain Owners / Registrant\s\s.*)')
    match = pattern.findall(data_result)
    # print match
    count = len(match)
    if match:
        domain_info['reg_name'] = match[0].split(':')[1].strip()
    # print domain_info
    return domain_info

def fr_manage(data_result):
    i = 0
    count = 0
    domain_info = {}
    pattern = re.compile(r'(holder-c:.*|nic-hdl:.*|contact:.*)')
    match = pattern.findall(data_result)
    # print match
    count  = len(match)
    for i in range(count):
        if match[i].split(':')[0].strip() == 'holder-c':
            holder = match[i].split(':')[1].strip()
        if match[i].split(':')[0].strip()=='nic-hdl' and match[i].split(':')[1].strip()==holder:
            try:
                domain_info['reg_name'] = match[i+1].split(':')[1].strip()
                break
            except:
                pass
    return domain_info

def ve_manage(data_result):

    domain_info = {}
    pattern = re.compile(r'(Titular:\s\s\s.*)')
    match = pattern.findall(data_result)
    # print match
    # print match[0].split('\t\t')
    count = len(match)
    if match:
        domain_info['reg_name'] = match[0].split('\t\t')[0].split(':')[1].strip()
        domain_info['reg_email'] = match[0].split('\t\t')[1].strip()
    # print domain_info
    return domain_info

def by_manage(data_result):

    domain_info = {}
    pattern = re.compile(r'(Registrar:.*)')
    match = pattern.findall(data_result)
    # print match
    # print match[0].split('\t\t')
    count = len(match)
    if match:
        domain_info['reg_name'] = match[0].split(':')[1].strip()
    # print domain_info
    return domain_info

def lv_manage(data_result):

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
    # print domain_info
    return domain_info