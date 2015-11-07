# coding=utf-8
import urllib2
import requests
import socket
import json
from urlparse import urlparse
from requests.utils import quote
from bs4 import BeautifulSoup

#if using proxy its.ac.id
def connproxy():
    proxy = urllib2.ProxyHandler({'http':'http://arie.priyambadha10@mhs.if.its.ac.id:118957592@proxy.its.ac.id:8080'})
    auth = urllib2.HTTPBasicAuthHandler()
    opener = urllib2.build_opener(proxy, auth, urllib2.HTTPHandler)
    urllib2.install_opener(opener)

#get domain from raw url
def getdomain(url):
    #urlparse berguna untuk membagi URL menjadi 6 komponen: scheme://netloc/path;parameters?query#fragment
    parse_result = urlparse(url)
    if(parse_result.netloc == ""):
        domain = parse_result.path
        if(domain[:1] == "."):
            domain = domain[1:]
    else:
        domain = parse_result.netloc

    try:
        #cek apakah IP address atau bukan
        socket.inet_aton(domain)
        return domain
    except:
        #buang subdomain www karena bukan domain name
        if(domain[:4] == "www."):
            domain = domain[4:]
        #split domain kedalam array var tmp berdasarkan titik
        tmp = domain.split(".")
        #dilakukan pengecekan jika terdapat lebih dari dua part substring, misal: google.co.uk, google.co.id
        if(len(tmp) > 2):
            #GENERIC TLD = com, co, net, org, gov, mil, edu, dan int
            #dilakukan pengecekan pada array kedua terakhir terhadap GENERIC_TLD
            #misal: *.co.uk, *co.id
            if (tmp[-2] in GENERIC_TLD):
                return tmp[-3] + "." + tmp[-2] + "." + tmp[-1]
            #jika array kedua terakhir merupakan SLD, misal: *.com, *.nl
            else:
                return tmp[-2] + "." + tmp[-1]
        #langsung direturn jika hanya terdapat satu titik, misal: google.com
        else:
            return domain

#Fitur 1 - Foreign Anchor
def fitur1(url):
    request = urllib2.Request(url, headers = headers)
    html = urllib2.urlopen(request).read()
    soup = BeautifulSoup(html)
    anchor = soup.find_all("a")

    #n foreign anchor
    #print anchor
    print len(anchor)
    nfa = 0
    for i in anchor:
        #terkadang ada tag a yang tidak memiliki attribut href
        if(i.has_attr("href")):
            link_anchor = i["href"]
        else:
            continue

        print link_anchor

        #javascript bukan link maka langsung dipass saja
        if(link_anchor[:10] == "javascript"):
            pass
        else:
            parse_result = urlparse(link_anchor)
            if(parse_result.scheme == ""): #relatif url pasti mengarah kesitus yang sama maka langsung dipass saja
                pass
            else:
                if(link_anchor[:2] == "//"):
                    link_anchor = link_anchor[2:]
                    if(getdomain(link_anchor) == getdomain(url)):
                        pass
                    else:
                        print "FOREIGN ANCHOR"
                        nfa += 1
                else:
                    if(getdomain(link_anchor) == getdomain(url)):
                        pass
                    else:
                        print "FOREIGN ANCHOR"
                        nfa += 1

    print nfa

    if(nfa > 5):
        return -1
    else:
        return 1

#Fitur 2 - Nil Anchor
def fitur2(url):
    request = urllib2.Request(url, headers = headers)
    html = urllib2.urlopen(request).read()
    soup = BeautifulSoup(html)
    anchor = soup.find_all("a")

    for i in anchor:
        if(i.has_attr("href")):
            link_anchor = i["href"]
        else:
            continue

        print link_anchor

        if(link_anchor == NIL_ANCHOR):
            return -1

    return 1

#Fitur 3 - IP Address
def fitur3(url):
    try:
        socket.inet_aton(urlparse(url).netloc)
        return -1
    except:
        return 1

#Fitur 4 - Dots in Page Address
def fitur4(url):
    if(url.count(".") > 5):
        return -1
    else:
        return 1

#Fitur 6 - Slash in Page Address
def fitur6(url):
    if(url.count("/")-2) >= 5:
        return -1
    else:
        return 1

#Fitur 9 - Using @ Symbol
def fitur9(url):
    tmp = urlparse(url).netloc
    if(tmp[-1] == "\n"):
        cekIndexAt = tmp[-2]
    else:
        cekIndexAt = tmp[-1]
    print cekIndexAt

    if(cekIndexAt == "@"):
        return -1
    else:
        return 1

#Fitur 13 - Cookie
def fitur13(url):
    domain = getdomain(url)
    print "DOMAIN PADA URL DATASET: " + domain
    request = requests.get(url, headers = headers)
    cookies = request.cookies.list_domains()

    if(len(cookies) == 0): #jika tidak terdapat cookie sama sekali
        return 2
    else:
        for i in cookies:
            print "DOMAIN PADA COOKIE: " + getdomain(i)
            if(getdomain(i) == domain): #own domain
                flag = 1
            else:
                return -1 #foreign domain

    if(flag == 1):
        return 1

#Fitur 14 - SSL Certificate
def fitur14(url):
    if(url[:5] == "https"):
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

    #menggunakan mesin pencarian Google CSE
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
    #ubah url kedalam bentuk encoding UTF-8 karena paramter tidak boleh mengandung Reserved characters
    url = quote(url, safe="")
    key = "AIzaSyBKfwvzDYmnSM1yM9dZkZQ08PxfG99n0hQ"
    url = "https://sb-ssl.google.com/safebrowsing/api/lookup?client=skripsi_phishing&key=" + key + "&appver=1.0.0&pver=3.1&url=" + url

    request = urllib2.urlopen(url).read()
    print urllib2.urlopen(url).getcode()
    print request
    if(request == "phishing" or request == "malware"):
        return -1
    else:
        return 1

if __name__ == "__main__":
    #fake user agents
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1"}
    GENERIC_TLD = ["com", "co", "gov", "net", "org", "int", "edu", "mil"]
    NIL_ANCHOR = ["", "javascript:;", "javascript:void(0)", "#"]

    #get database
    with open("dataset.txt", "r") as file:
        data = file.readlines()

    n = 0
    #connproxy()
    while n < len(data):
        url = data[n]
        """
        url = "http://www.unil.ch/central/home/legalinformation.html"
        request = urllib2.Request(url, headers = headers)
        html = urllib2.urlopen(request).read()
        soup = BeautifulSoup(html)
        anchor = soup.find_all("a")

        a = 0
        for i in anchor:
            #print a+1
            #print i
            if(i.has_key("href")):
                print i["href"]

            a += 1
        """

        print url

        try:
            #print urllib2.urlopen("http://www.kaskus.co.id").read()
            #print fitur17(url)
            print fitur17(url)
        except urllib2.URLError as e:
            print e.reason
        except urllib2.HTTPError as e:
            print e.reason
        except:
            print ""

        n += 1
    print n