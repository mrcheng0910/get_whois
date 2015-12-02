#encoding:utf-8
from tld import get_tld
from urlparse import urlparse
http = 'http://'
url = 'unread-help-msg.email'
url = http + url
try:
    res = get_tld(url, as_object=True)
    print res.tld
    print res.suffix

except:
    parsed = urlparse(url)  # urlparse格式化
    domain = parsed.netloc  # 提取域名
    suffix = domain.split('.')[-1]
    print domain
    print suffix

