# coding=utf-8
import urllib2
import requests
import socket
import json
from urlparse import urljoin
from bs4 import BeautifulSoup

#if using proxy its.ac.id
def connproxy():
    proxy = urllib2.ProxyHandler({'http':'http://arie.priyambadha10@mhs.if.its.ac.id:118957592@proxy.its.ac.id:8080'})
    auth = urllib2.HTTPBasicAuthHandler()
    opener = urllib2.build_opener(proxy, auth, urllib2.HTTPHandler)
    urllib2.install_opener(opener)

#get domain from raw url
def getdomain(url):
    if(url[:7] == "http://" or url[:8] == "https://"):
        index_double_slash = url.find("/") + 1
        suburl = url[index_double_slash + 1:]

    if("/" in suburl):
        domain = suburl[:suburl.find("/")]
    else:
        domain = suburl

    try:
        socket.inet_aton(domain)
        return domain
    except:
        if(domain.count(".") == 1):
            return domain
        else:
            return domain

#Fitur 1 - Foreign Anchor
def fitur1(url):
    request = urllib2.Request(url, headers = headers)
    html = urllib2.urlopen(request).read()
    soup = BeautifulSoup(html)
    anchor = soup.find_all("a")

    for i in anchor:
        #ubah relatif URL ke absolut URL
        #print i["href"]
        print urljoin(url, i["href"])

#Fitur 6 - Slash in Page Address
def fitur6(url):
    if(url.count("/")-2) >= 5:
        return -1
    else:
        return 1

#Fitur 13 - Cookie
def fitur13(url):
    request = requests.get(url, headers = headers)
    cookies = request.cookies.list_domains()

    #initial no cookies found
    flag = 2
    for i in cookies:
        if(getdomain(i) in url):
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
def fitur14(url):
    if(url[:4] == "http"):
        try:
            #certs.pem : CA Bundle is extracted from the Mozilla Included CA Certificate List.
            requests.get(url)
            return 1
        except:
            return -1
    else:
        return -1

#Fitur 15 - Search Engine
def fitur15(url):
    key = "AIzaSyBKfwvzDYmnSM1yM9dZkZQ08PxfG99n0hQ"
    cx = "015058113956565325925"
    q = url

    request = urllib2.Request("https://www.googleapis.com/customsearch/v1?key=" + key + "&cx=" + cx + ":awgpmf5zb5k&q=" + q, headers = headers)
    response = urllib2.urlopen(request)
    data = json.load(response)
    result = data["items"]

    for i in result:
        print i["link"]

"""
Response Codes

The server generates the following HTTP response codes for the GET request:

    200: The queried URL is either phishing, malware, or both; see the response body for the specific type.
    204: The requested URL is legitimate and no response body is returned.
    400: Bad Request—The HTTP request was not correctly formed.
    401: Not Authorized—The API key is not authorized.
    503: Service Unavailable—The server cannot handle the request. Besides the normal server failures, this can also indicate that the client has been “throttled” for sending too many requests.

Possible reasons for the Bad Request (HTTP code 400):

    Not all required CGI parameters are specified.
    Some of the CGI parameters are empty.
    The queried URL is not a valid URL or not properly encoded.
"""
#Fitur 17 - Blacklist
def fitur17(url):
    key = "AIzaSyBKfwvzDYmnSM1yM9dZkZQ08PxfG99n0hQ"
    url = "https://sb-ssl.google.com/safebrowsing/api/lookup?client=skripsi_phishing&key=" + key + "&appver=1.0.0&pver=3.1&url=" + url

    #try:
    request = urllib2.urlopen(url).read()
    """
    except:
        print "GAGAL CEK BLACKLIST"
    """
    if(request == "phishing" or request == "malware"):
        return -1
    else:
        return 1

if __name__ == "__main__":
    #fake user agents
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1"}

    #get database
    with open("dataset.txt", "r") as file:
        data = file.readlines()

    n = 0
    #connproxy()
    while n < len(data):
        url = data[n]
        try:
            #print fitur_6(data[n])
            #print fitur_13(data[n])
            #print get_domain(data[n])
            print url
            print fitur1(url)

        except:
            pass

        n += 1