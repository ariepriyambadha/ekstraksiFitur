"""Ekstraksi Fitur Deteksi Situs Phishing."""
# -*- coding: utf-8 -*-

import urllib2
import socket
import requests
import json
import time
import whois
import nltk
import csv
import math
import ssl

from bs4 import BeautifulSoup
from lxml import html
from lxml.html import parse
from urlparse import urlparse
from urlparse import urljoin
from requests.utils import quote
from nltk.corpus import stopwords
from collections import Counter
from OpenSSL import crypto

generic_tld = ["com", "co", "gov", "net", "org", "int", "edu", "mil"]
nil_anchors = ["", "javascript:;", "javascript:void(0)", "#"]
headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0"}
key_api = "AIzaSyBKfwvzDYmnSM1yM9dZkZQ08PxfG99n0hQ"
cx = "015058113956565325925"

def connect_proxy():
    proxy = urllib2.ProxyHandler({'http':'http://arie.priyambadha10@mhs.if.its.ac.id:118957592@proxy.its.ac.id:8080'})
    auth = urllib2.HTTPBasicAuthHandler()
    opener = urllib2.build_opener(proxy, auth, urllib2.HTTPHandler)
    urllib2.install_opener(opener)

def check_url(url):
    if(urlparse(url).scheme == ""):
        # 0 = Relative URL
        return 0
    else:
        # 1 = Absolute URL
        return 1

def tfidf(n, N, docFreq):
    tf = math.sqrt(n/N)
    idf = 1 + math.log((6053398)/(docFreq+1))

    return tf * idf

def get_domain(url):
    new_url = url.lower()

    #urlparse berguna untuk membagi URL menjadi 6 komponen: scheme://netloc/path;parameters?query#fragment
    parse_result = urlparse(new_url)

    if(parse_result.netloc == ""):
        domain = parse_result.path
    else:
        domain = parse_result.netloc

    try:
        socket.inet_aton(domain)
        return domain
    except:
        if(domain[:4] == "www."):
            domain = domain[4:]

        tmp = domain.split(".")

        if(len(tmp) > 2):
            if (tmp[-2] in generic_tld):
                return tmp[-3] + "." + tmp[-2] + "." + tmp[-1]
            else:
                return tmp[-2] + "." + tmp[-1]
        else:
            return domain

def get_identity(url, soup, corpus):
    tokens = []

    # ekstrak konten title
    title = soup.find("title")
    tmp = nltk.word_tokenize(str(title.string))

    for i in tmp:
        if(len(i) > 2):
            tokens.append(i)

    # ekstrak konten meta description & keywords
    meta_key = []
    meta_desc = []

    meta = soup("meta")
    for i in meta:
        if (i.has_attr("name")):
            if (i.has_attr("content")):
                if (i["name"] == "keywords"):
                    meta_key.append(i["content"])
                elif (i["name"] == "description"):
                    meta_desc.append(i["content"])

    for i in meta_desc:
        tmp = nltk.word_tokenize(i)
        for j in tmp:
            if(len(j) > 2):
                tokens.append(j)

    for i in meta_key:
        tmp = nltk.word_tokenize(i)
        for j in tmp:
            if(len(j) > 2):
                tokens.append(j)

    anchor = soup("a")
    for i in anchor:
        if (i.has_attr("href")):
            anchor = get_domain(urljoin(url, i["href"]))
            new_anchor = anchor[:str(anchor).find(".")]
            if(len(new_anchor) > 2):
                tokens.append(new_anchor)

    stop_words = set(stopwords.words("english"))

    final_tokens = []
    for i in tokens:
        if(str(i).lower() not in stop_words):
            final_tokens.append(str(i).lower())

    raw_list_tfidf = {}
    N = len(final_tokens)
    # hitung banyaknya terms pada list
    list_terms = Counter(final_tokens)
    for i in list_terms:
        if(i in corpus):
            docFreq = corpus[i]
        else:
            docFreq = 0
        score = tfidf(float(list_terms[i]), float(N), float(docFreq))

        raw_list_tfidf[i] = score

    set_id = []
    for key, value in Counter(raw_list_tfidf).most_common(5):
        set_id.append(key)

    return set_id

# Fitur 1: Foreign Anchor
def foreign_anchor(url, soup):
    anchor = soup("a")

    nfa = 0
    for i in anchor:
        if(i.has_attr("href")):
            href = str(i["href"]).lower()
            # print href

            # cek apakah href merupakan absolute url atau bukan? 1 = absolute URL, 0 = relatif URL
            if(check_url(href) == 1 or href[:2] == "//"):
               if(get_domain(href) != get_domain(url)):
                   nfa += 1

    if(nfa > 5):
        return -1
    else:
        return 1

# Fitur 2: Nil Anchor
def nil_anchor(soup):
    anchor = soup("a")
    for i in anchor:
        if(i.has_attr("href")):
            href = str(i["href"]).lower()
            if(href in nil_anchors):
                return -1

    return 1

# Fitur 3: IP Address
def ip_addr(url):
    try:
        socket.inet_aton(urlparse(url).netloc)
        return -1
    except:
        return 1

# Fitur 4: Dots in Page Address
def dots_page_addr(url):
    if(url.count(".") > 5):
        return -1
    else:
        return 1

# Fitur 5: Dots in URLs
def dots_url(url):
    page = parse(urllib2.urlopen(url)).getroot()
    page_string = html.tostring(page)
    list_url = html.make_links_absolute(page_string, base_url = url)

    nd = 0
    for i in list_url:
        #print i
        nd += i.count(".")

    if(len(list_url) == 0):
        return 1
    if(nd/len(list_url) > 5.0):
        return -1
    else:
        return 1

# Fitur 6: Slash in Page Address
def slash_page_addr(url):
    if((url.count("/") - 2) > 5):
        return -1
    else:
        return 1

# Fitur 7: Slash in URLs
def slash_url(url):
    page = parse(urllib2.urlopen(url)).getroot()
    page_string = html.tostring(page)
    list_url = html.make_links_absolute(page_string, base_url = url)

    ns = 0
    for i in list_url:
        ns += i.count("/") - 2

    if(len(list_url) == 0):
        return 1
    if(ns/len(list_url) >= 5.0):
        return -1
    else:
        return 1

# Fitur 8: Foreign Anchor in Identity Set
def foreign_anchor_in_id(url, soup, corpus):
    set_id = get_identity(url, soup, corpus)
    anchor = soup("a")

    nfa = 0
    for i in anchor:
        if(i.has_attr("href")):
            href = str(i["href"]).lower()
            # print href
            domain = get_domain(urljoin(url, href))
            new_domain = domain[:str(domain).find(".")]

            if(new_domain not in set_id):
                return -1

    return 1

# Fitur 9: Using @ Symbol
def at_symbol(url):
    if(str(urlparse(url).netloc).find("@") > 0):
        return -1
    else:
        return 1

# Fitur 10: Server Form Handler(SFH)
def sfh(url, soup):
    form = soup("form")

    for i in form:
        if(i.has_attr("action")):
            action = str(i["action"]).lower()

            if(action == "" or action == "#" or action == "void"):
                return -1
            elif(check_url(action) == 1 or action[:2] == "//"):
                if(get_domain(url) != get_domain(action)):
                    return -1

    return 1

# Fitur 11: Foreign Request URLs
def foreign_request(url, soup):
    # soup link tag
    link = soup("link")
    for i in link:
        if(i.has_attr("href")):
            href = i["href"]
            if(check_url(href) == 1 or href[:2] == "//"):
                if(get_domain(url) != get_domain(href)):
                    return -1

    # soup script tag
    script = soup("script")
    for i in script:
        if(i.has_attr("src")):
            src = i["src"]
            if(check_url(src) == 1 or src[:2] == "//"):
                if(get_domain(url) != get_domain(src)):
                    return -1

    # soup img tag
    img = soup("img")
    for i in img:
        if(i.has_attr("src")):
            src = i["src"]
            if(check_url(src) == 1 or src[:2] == "//"):
                if(get_domain(url) != get_domain(src)):
                    return -1

    # soup body tag
    body = soup("body")
    for i in body:
        if(i.has_attr("background")):
            background = i["background"]
            if(check_url(background) == 1 or background[:2] == "//"):
                if(get_domain(url) != get_domain(background)):
                    return -1

    # soup object tag
    object = soup("object")
    for i in object:
        if(i.has_attr("codebase")):
            codebase = i["codebase"]
            if(check_url(codebase) == 1 or codebase[:2] == "//"):
                if(get_domain(url) != get_domain(codebase)):
                    return -1

    # soup applet tag
    applet = soup("applet")
    for i in object:
        if(i.has_attr("codebase")):
            codebase = i["codebase"]
            if(check_url(codebase) == 1 or codebase[:2] == "//"):
                if(get_domain(url) != get_domain(codebase)):
                    return -1

        if(i.has_attr("code")):
            code = i["code"]
            if(check_url(code) == 1 or code[:2] == "//"):
                if(get_domain(url) != get_domain(code)):
                    return -1

    # soup frame tag
    frame = soup("frame")
    for i in frame:
        if(i.has_attr("src")):
            src = i["src"]
            if(check_url(src) == 1 or src[:2] == "//"):
                if(get_domain(url) != get_domain(src)):
                    return -1

    # soup iframe tag
    iframe = soup("iframe")
    for i in iframe:
        if(i.has_attr("src")):
            iframe = i["src"]
            if(check_url(iframe) == 1 or iframe[:2] == "//"):
                if(get_domain(url) != get_domain(iframe)):
                    return -1

    # soup input tag
    input = soup("input")
    for i in input:
        if(i.has_attr("src")):
            src = i["src"]
            if(check_url(src) == 1 or src[:2] == "//"):
                if(get_domain(url) != get_domain(src)):
                    return -1

    return 1

# Fitur 12: Foreign Request in Identity Set
def foreign_request_in_id(url, soup, corpus):
    set_id = get_identity(url, soup, corpus)
    # soup link tag
    link = soup("link")
    for i in link:
        if(i.has_attr("href")):
            href = str(i["href"]).lower()
            # print href
            domain = get_domain(urljoin(url, href))
            new_domain = domain[:str(domain).find(".")]

            if(new_domain not in set_id):
                return -1

    # soup script tag
    script = soup("script")
    for i in script:
        if(i.has_attr("src")):
            href = str(i["src"]).lower()
            # print href
            domain = get_domain(urljoin(url, href))
            new_domain = domain[:str(domain).find(".")]

            if(new_domain not in set_id):
                return -1

    # soup img tag
    img = soup("img")
    for i in img:
        if(i.has_attr("src")):
            href = str(i["src"]).lower()
            # print href
            domain = get_domain(urljoin(url, href))
            new_domain = domain[:str(domain).find(".")]

            if(new_domain not in set_id):
                return -1

    # soup body tag
    body = soup("body")
    for i in body:
        if(i.has_attr("background")):
            href = str(i["background"]).lower()
            # print href
            domain = get_domain(urljoin(url, href))
            new_domain = domain[:str(domain).find(".")]

            if(new_domain not in set_id):
                return -1

    # soup object tag
    object = soup("object")
    for i in object:
        if(i.has_attr("codebase")):
            href = str(i["codebase"]).lower()
            # print href
            domain = get_domain(urljoin(url, href))
            new_domain = domain[:str(domain).find(".")]

            if(new_domain not in set_id):
                return -1

    # soup applet tag
    applet = soup("applet")
    for i in object:
        if(i.has_attr("codebase")):
            href = str(i["codebase"]).lower()
            # print href
            domain = get_domain(urljoin(url, href))
            new_domain = domain[:str(domain).find(".")]

            if(new_domain not in set_id):
                return -1

        if(i.has_attr("code")):
            href = str(i["code"]).lower()
            # print href
            domain = get_domain(urljoin(url, href))
            new_domain = domain[:str(domain).find(".")]

            if(new_domain not in set_id):
                return -1

    # soup frame tag
    frame = soup("frame")
    for i in frame:
        if(i.has_attr("src")):
            href = str(i["src"]).lower()
            # print href
            domain = get_domain(urljoin(url, href))
            new_domain = domain[:str(domain).find(".")]

            if(new_domain not in set_id):
                return -1

    # soup iframe tag
    iframe = soup("iframe")
    for i in iframe:
        if(i.has_attr("src")):
            href = str(i["src"]).lower()
            # print href
            domain = get_domain(urljoin(url, href))
            new_domain = domain[:str(domain).find(".")]

            if(new_domain not in set_id):
                return -1

    # soup input tag
    input = soup("input")
    for i in input:
        if(i.has_attr("src")):
            href = str(i["src"]).lower()
            # print href
            domain = get_domain(urljoin(url, href))
            new_domain = domain[:str(domain).find(".")]

            if(new_domain not in set_id):
                return -1

    return 1

# Fitur 13: Cookie
def cookies(url):
    request = requests.get(url, headers = headers)
    cookies = request.cookies.list_domains()

    flag = 0
    if(len(cookies) == 0):
        return 2
    else:
        for domain_cookies in cookies:
            if(domain_cookies[:1] == "."):
                domain_cookies = domain_cookies[1:]
            if(get_domain(domain_cookies) == get_domain(url)):
                flag = 1
            else:
                return -1

    if(flag == 1):
        return 1
    else:
        return 2

# Fitur 14: SSL Sertifikat
def ssl_cert(url):
    if(url[:5] == "https"):
        #print get_domain(url)
        server_cert = ssl.get_server_certificate((get_domain(url), 443))
        x509 = crypto.load_certificate(crypto.FILETYPE_PEM, server_cert)

        #print server_cert

        cert_info = x509.get_subject().get_components()
        #print cert_info

        for i in cert_info:
            (key, value) = i

            if(key == "CN"):
                CN = value
                break

        if(CN[:2] == "*."):
            new_CN = CN[2:]
        elif(CN[:1] == "."):
            new_CN = CN[1:]
        else:
            new_CN = CN

        domain_CN = get_domain(new_CN)

        #print domain_CN
        #print x509.get_issuer()
        #print x509.has_expired()
    else:
        return -1

# Fitur 15: Search Engine
def search_engine(url):
    # menggunakan mesin pencarian Google CSE
    request = urllib2.Request("https://www.googleapis.com/customsearch/v1?key=" + key_api + "&cx="
                              + cx + ":awgpmf5zb5k&q=" + url, headers = headers)
    response = urllib2.urlopen(request)
    data = json.load(response)
    search_information = data["searchInformation"]

    flag = 0
    if(search_information["totalResults"] == "0"):
        return -1
    else:
        n = 0
        result = data["items"]
        for i in result:
            if(n == 5):
                break
            if(url == i["link"]):
                flag = 1

            n += 1

    if(flag == 1):
        return 1
    else:
        return -1

# Fitur 16: Whois Lookup
def whois_lookup(url):
    url_parse = urlparse(url)
    new_url = str(url_parse.scheme) + "://" + str(url_parse.netloc)

    try:
        w = whois.whois(new_url)
        #print w
        return 1
    except:
        return -1

# Fitur 17: Blacklist
def blacklist(url):
    url = quote(url, safe="")
    request_url = "https://sb-ssl.google.com/safebrowsing/api/lookup?client=skripsi_phishing&key=" \
                  + key_api + "&appver=1.0.0&pver=3.1&url=" + url

    #print requests.get(request_url).status_code
    request = requests.get(request_url).text

    if(request == "phishing" or request == "malware"):
        return -1
    else:
        return 1

def main():
    with open("dataset.txt", "r") as file:
        dataset = file.readlines()

    corpus = {}
    with open("corpus/WebCorpus2006_min10.txt", "rb") as csv_file:
        csv_reader = csv.reader(csv_file, delimiter="\t")
        for row in csv_reader:
            corpus[row[0]] = row[1]

    n = 30

    print "n\t1\t2\t3\t4\t5\t6\t7\t8\t9\t10\t11\t12\t13\t14\t15\t16\t17"
    while n < len(dataset):
        # hapus karakter new lines di akhir url
        url = dataset[n].rstrip("\n")
        #print url

        try:
            request = urllib2.Request(url, headers = headers)
            status_code = urllib2.urlopen(request).getcode()

            if(status_code == 200):
                response = urllib2.urlopen(request).read()
                soup = BeautifulSoup(response)

                try:
                    f1 = foreign_anchor(url, soup)
                except:
                    f1 = 0

                try:
                    f2 = nil_anchor(soup)
                except:
                    f2 = 0

                try:
                    f3 = ip_addr(url)
                except:
                    f3 = 0

                try:
                    f4 = dots_page_addr(url)
                except:
                    f4 = 0

                try:
                    f5 = dots_url(url)
                except:
                    f5 = 0

                try:
                    f6 = slash_page_addr(url)
                except:
                    f6 = 0

                try:
                    f7 = slash_url(url)
                except:
                    f7 = 0

                try:
                    f8 = foreign_anchor_in_id(url, soup, corpus)
                except:
                    f8 = 0

                try:
                    f9 = at_symbol(url)
                except:
                    f9 = 0

                try:
                    f10 = sfh(url, soup)
                except:
                    f10 = 0

                try:
                    f11 = foreign_request(url, soup)
                except:
                    f11 = 0

                try:
                    f12 = foreign_anchor_in_id(url, soup, corpus)
                except:
                    f12 = 0

                try:
                    f13 = cookies(url)
                except:
                    f13 = 0

                try:
                    f14 = 0
                except:
                    f14 = 0

                try:
                    f15 = search_engine(url)
                except:
                    f15 = 0

                try:
                    f16 = whois_lookup(url)
                except:
                    f16 = 0

                try:
                    f17 = blacklist(url)
                except:
                    f17 = 0

                print str(n + 1) + "\t" + str(f1) + "\t" + str(f2) + "\t" + str(f3) + "\t" + str(f4) + "\t" + str(f5) + "\t" \
                      + str(f6) + "\t" + str(f7) + "\t" + str(f8) + "\t" + str(f9) + "\t" + str(f10) + "\t" \
                      + str(f11) + "\t" + str(f12) + "\t" + str(f13) + "\t" + str(f14) + "\t" + str(f15) + "\t" \
                      + str(f16) + "\t" + str(f17)
            else:
                print str(n + 1) + "\t0\t0\t0\t0\t0\t0\t0\t0\t0\t0\t0\t0\t0\t0\t0\t0\t0"

        except urllib2.HTTPError as e:
            print str(n + 1) + "\t0\t0\t0\t0\t0\t0\t0\t0\t0\t0\t0\t0\t0\t0\t0\t0\t0"
        except urllib2.URLError as e:
            print str(n + 1) + "\t0\t0\t0\t0\t0\t0\t0\t0\t0\t0\t0\t0\t0\t0\t0\t0\t0"
        except socket.error as e:
            print str(n + 1) + "\t0\t0\t0\t0\t0\t0\t0\t0\t0\t0\t0\t0\t0\t0\t0\t0\t0"

        n += 1
        #time.sleep(5)

if __name__ == "__main__":
    main()