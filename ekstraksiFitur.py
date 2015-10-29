import urllib2
import requests
from bs4 import BeautifulSoup

#if using proxy its.ac.id
def connProxy():
    proxy = urllib2.ProxyHandler({'http':'http://arie.priyambadha10@mhs.if.its.ac.id:118957592@proxy.its.ac.id:8080'})
    auth = urllib2.HTTPBasicAuthHandler()
    opener = urllib2.build_opener(proxy, auth, urllib2.HTTPHandler)
    urllib2.install_opener(opener)

#get domain name from raw url
def getDomainName(url):
    indexDoubleSlash = url.find("/") + 1
    subUrl = url[indexDoubleSlash + 1:]
    if "/" in subUrl:
        domainName = subUrl[:subUrl.find("/")]
    else:
        domainName = subUrl

    return domainName

if __name__ == "__main__":
    #fake user agents
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1"}

    #get database
    with open("dataset.txt", "r") as file:
        data = file.readlines()

    n = 0
    while n < len(data):
        url = data[n]
        try:
            r = requests.get(url, headers=headers)
            print url
            print r.cookies

            request = urllib2.Request(url, headers = headers)
            response = urllib2.urlopen(request)
            html = response.read()
            soup = BeautifulSoup(html)
            anchor = soup.find_all("form")

            print url
            print response.getcode()
            for i in anchor:
                print i["action"]

        except:
            pass

        n += 1