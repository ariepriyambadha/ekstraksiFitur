import urllib2
import requests
import socket

#if using proxy its.ac.id
def conn_proxy():
    proxy = urllib2.ProxyHandler({'http':'http://arie.priyambadha10@mhs.if.its.ac.id:118957592@proxy.its.ac.id:8080'})
    auth = urllib2.HTTPBasicAuthHandler()
    opener = urllib2.build_opener(proxy, auth, urllib2.HTTPHandler)
    urllib2.install_opener(opener)

#get domain from raw url
def get_domain(url):
    if(url[:7] == "http://" or url[:8] == "https://"):
        index_double_slash = url.find("/") + 1
        sub_url = url[index_double_slash + 1:]

    if("/" in sub_url):
        domain = sub_url[:sub_url.find("/")]
    else:
        domain = sub_url

    try:
        socket.inet_aton(domain)
        return domain
    except:
        if(domain.count(".") == 1):
            return domain
        else:
            return domain

#Fitur 6 - Slash in Page Address
def fitur_6(url):
    if(url.count("/")-2) >= 5:
        return -1
    else:
        return 1

#Fitur 13 - Cookie
def fitur_13(url):
    request = requests.get(url, headers = headers)
    cookies = request.cookies.list_domains()

    #initial no cookies found
    flag = 2
    for i in cookies:
        if(get_domain(i) in url):
            #own domain
            flag = 1
        else:
            #foreign domain
            flag = -1
            return flag

    if(flag == 2):
        return 2
    else:
        return 1

#Fitur 14 - SSL Certificate
def fitur_14(url):
    try:
        requests.get(url, cert = "certs.der")
        return 1
    except:
        return -1

if __name__ == "__main__":
    #fake user agents
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1"}

    #get database
    with open("dataset.txt", "r") as file:
        data = file.readlines()

    n = 0
    #conn_proxy()
    while n < len(data):
        url = data[n]
        try:
            #print fitur_6(data[n])
            #print fitur_13(data[n])
            #print get_domain(data[n])
            print url
            print fitur_14(url)

        except:
            pass

        n += 1
    print n