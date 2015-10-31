import urllib2 
import whois
import requests
import cookielib
import json
import urllib
import socket
import ssl
import lucene
import jcc
from cookielib import CookieJar
from urllib2 import Request, build_opener, HTTPCookieProcessor, HTTPHandler
from bs4 import BeautifulSoup

###################----------------------------------------------- Fungsi Tambahan -----------------------------------------------#############################

def connProxy():
	proxy = urllib2.ProxyHandler({'http':'http://arie.priyambadha10@mhs.if.its.ac.id:118957592@proxy.its.ac.id:8080'})
	auth = urllib2.HTTPBasicAuthHandler()
	opener = urllib2.build_opener(proxy, auth, urllib2.HTTPHandler)
	urllib2.install_opener(opener)
	
def connProxy2():
	proxy = urllib2.ProxyHandler({'http':'http://asrama@its.ac.id:asramaits@proxy2.its.ac.id:8080'})
	auth = urllib2.HTTPBasicAuthHandler()
	opener = urllib2.build_opener(proxy, auth, urllib2.HTTPHandler)
	urllib2.install_opener(opener)
	
def toAbsolute(link, url):
	#Ubah http://www.kaskus.co.id -> http:
	if link[:2] == "//":
		indexTitikDua = url.find(":")
		link = url[:indexTitikDua + 1] + link
	#Back to root directory
	elif link[:1] == "/":
		indexSlash = url.find("/") + 1
		link2 = url[indexSlash + 1:]
		indexSlash2 = link2.find("/") + indexSlash + 1
		link = url[:indexSlash2] + link
	#Up one directory 
	elif str(link[:2]) == "..":
		indexLastSlash = url.rfind("/")
		link2 = url[:indexLastSlash]
		indexLastSlash = link2.rfind("/")
		if str(link2[indexLastSlash - 1:indexLastSlash]) == "/":
			link = str(link2 + link[2:])
		else:
			link = str(link2[:indexLastSlash] + link[2:])
	# Current directory
	elif link[:2] == "./":
		indexLastSlash = url.rfind("/")
		link = str(url[:indexLastSlash + 1] + link[2:])
	elif "mailto" in str(link) or link[:10] == "javascript":
		pass
	else:
		link = url[:-1] + link
	
	return link

def cekUrl(anchor):
	# 1 = absolute url
	# 2 = relative url
	# 3 = bukan url
	if(anchor[:4] == "http"):
		return 1
	elif(anchor[:3] == "../" or anchor[:2] == "./" or anchor[:1] == "/"):
		return 2
	elif(anchor[:1] == "#"):
		return 2
	elif(anchor[:2] == "//"):
		return 2
	elif(anchor[:6] == "mailto" or anchor[:10] == "javascript"):
		return 3
	elif(anchor == "" or anchor is None):
		return 3
	else:
		return 2

def getPath(url):
	# Asumsi setiap url yang ada memiliki string http://
	indexDoubleSlash = url.find("/") + 1
	subUrl = url[indexDoubleSlash + 1:]
	if "/" in subUrl:
		path = subUrl[:subUrl.find("/")]
	else:
		path = subUrl
		
	return path

def getDomain(url):
	domainName = url
	if(url[:4] == "www."):
		domainName = url[4:]
	if(url.count(".") == 1):
		pass
	elif(domainName.count(".") == 2):
		indexLastDot = url.rfind(".")
		# TLD = Top Level Domain
		TLD = url[indexLastDot + 1:]
		indexFirstDot = url.find(".")
		TLD2 = url[indexFirstDot + 1:indexLastDot]
		if(len(TLD) == 2 and len(TLD2) == 2):
			pass
		else:
			domainName = url[indexFirstDot + 1:]
	else:
		indexLastDot = url.rfind(".")
		TLD = url[indexLastDot + 1:]
		indexLastDot2 = url[:indexLastDot].rfind(".")
		TLD2 = url[indexLastDot2 + 1:indexLastDot]
		if(len(TLD) == 2 and len(TLD2) == 2):
			# MLD = Mid Level Domain
			indexLastDot3 = url[:indexLastDot2].rfind(".")			
			domainName = url[indexLastDot3 + 1:]
		else:
			domainName = url[indexLastDot2 + 1:]
		
	return domainName

###################----------------------------------------------- Fitur Ekstraksi -----------------------------------------------#############################

#Fitur 1 - Foreign Anchor
def cekForeignAnchor(url):
	headers = {'User-Agent' : "Mozilla/5.0 (Windows NT 6.2; rv:37.0) Gecko/20100101 Firefox/37.0"}
	request = urllib2.Request(url, headers = headers)
	html = urllib2.urlopen(request).read()
	soup = BeautifulSoup(html)
	anchor = soup.findAll("a")
	
	domainName = getDomain(getPath(url))
	nForeign = 0
	nLegit = 0
	
	for i in anchor:
		try:
			flag = cekUrl(i["href"])
			if(flag == 1):
				tmp = getDomain(getPath(i["href"]))
			elif(flag == 2):
				tmp = getDomain(getPath(toAbsolute(i["href"], url)))
			elif(flag == 3):
				tmp = i["href"]
				
			if(domainName == tmp):
				nLegit = nLegit + 1
			else:
				nForeign = nForeign + 1
						
		except:
			pass
			
	if(nForeign == 0):
		F1 = 1
	elif(nLegit / (nLegit + nForeign) >= 0.5):
		F1 = 1
	else:
		F1 = -1
		
	return F1
		
#Fitur 2 - Nil Anchor
def cekNilAnchor(url):
	headers = {'User-Agent' : "Mozilla/5.0 (Windows NT 6.2; rv:37.0) Gecko/20100101 Firefox/37.0"}
	request = urllib2.Request(url, headers = headers)
	html = urllib2.urlopen(request).read()
	soup = BeautifulSoup(html)
	anchor = soup("a", {"href": True})
	
	F2 = 1
	for anchor in anchor:
		if(anchor["href"] == "#" or anchor["href"] == "javascript:void(0);" or anchor["href"] == "javascript:;" or anchor["href"] == "javascript:void(0)"):
			F2 = -1
			print anchor["href"]
	
	return F2
	
#Fitur 3 - IP address
def cekIP(url):
	url = getPath(url)
	try	:
		socket.inet_aton(url)
		F3 = -1
	except:
		F3 = 1
		
	return F3

#Fitur 4 - Dots in Page Address
def cekTitik(url):
	if(url.count(".") > 5):
		F4 = -1
	else:
		F4 = 1
		
	return F4
	
#Fitur 5 - Dots in URL
def cekDotsUrl(link):
	request = urllib2.Request(url, headers = headers)
	html = urllib2.urlopen(request).read()
	soup = BeautifulSoup(html)
	anchor = soup.findAll("a")
	
	nAnchor = len(anchor)
	allDot = 0
	
	for anchor in anchor:
		tmp = toAbsolute(anchor["href"])
		nDot = tmp.count(".")
		allDot = allDot + nDot
	
	avgDot = float(allDot) / float(nAnchor)
	
	if(avgDot > 5.0):
		F5 = -1
	else:
		F5 = 1
	
	return F5
	
#Fitur 6 - Slash in Page Address
def cekGarisMiring(url):
	if(link.count("/") >= 5):
		F6 = -1
	else:
		F6 = 1
		
	return F6
	
#Fitur 7 - Slash in URL
def cekSlashUrl(link):
	request = urllib2.Request(url, headers = headers)
	html = urllib2.urlopen(request).read()
	soup = BeautifulSoup(html)
	anchor = soup.findAll("a")
	
	nAnchor = len(anchor)
	allSlash = 0
	
	for anchor in anchor:
		tmp = toAbsolute(anchor["href"])
		nSlash = tmp.count("/")
		allSlash = allSlash + nSlash
	
	avgSlash = float(allSlash) / float(nAnchor)
	
	if(avgSlash >= 5.0):
		F7 = -1
	else:
		F7 = 1
	
	return F7

#Fitur 8 - Foreign Anchor in Identity Set


#Fitur 9 - Using @ Symbol
def cekSymbol(link):
	if(link.find('@') == 1):
		F9 = -1
	else:
		F9 = 1
		
	return F9

#Fitur 10 - Server Form Handler (SFH)
def cekSFH(link):
	domainNamePA = urlToDomain(link)
	headers = {'User-Agent':'Mozilla/5.1'}
	request = urllib2.Request(link, headers = headers)
	html = urllib2.urlopen(request).read()
	soup = BeautifulSoup(html)
	form = soup("form")
	
	if(len(form) == 0):
		return 1
	else:
		for action in form:
			try:
				tmp = getAbsolute(action["action"])
				actionForm = getDomain(getPath(tmp))
				
				# Kondisi Kedua
				if(str(action["action"]) == ""):
					return -1
				# Idem
				elif(action["action"] is None):
					return -1
				# Kondisi Ketiga
				elif(str(action["action"]) == "#"):
					return -1
				# Kondisi Keempat, mungkin masih ada kondisi lain yang menyebabkan nilai action itu Void
				elif(str(action["action"]) == "javascript:void(0);" or str(action["action"]) == "javascript:void(0)"):
					return -1
				else:
					if(actionForm == domainNamePA):
						return 1
					elif(actionForm != domainNamePA):
						return -1
			except:
				pass


"""
#Fitur 11 - Foreign Request
def checkForeignRequest(url):
	html = urllib2.urlopen(url).read()
	soup = BeautifulSoup(html)

	img = soup.find_all("img")
	script = soup.find_all("script")
	link = soup.find_all("link")
	body = soup.find_all("body")
	object = soup.find_all("object")
	applet = soup.find_all("applet")

	for i in img:
		try:
			print urlToDomain(getAbsoluteUrl(i["src"]))
		except:	
			pass
		
	for i in script:
		try:
			print urlToDomain(getAbsoluteUrl(i["src"]))
		except:	
			pass
			
	for i in link:
		try:
			print urlToDomain(getAbsoluteUrl(i["href"]))
		except:	
			pass
		
	for i in body:
		try:
			print urlToDomain(getAbsoluteUrl(i["background"]))
		except:	
			pass
			
	for i in object:
		try:
			print urlToDomain(getAbsoluteUrl(i["data"]))
		except:	
			pass
			
	for i in applet:
		try:
			print urlToDomain(getAbsoluteUrl(i["code"]))
		except:	
			pass
"""
			
#Fitur 12 - Foreign Request in Identity Set		

#Fitur 13 - Cookie
def cekCookie(link):
	cj = CookieJar()
	opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj))
	r = opener.open(link)
	
	domainName = getDomain(getPath(link))
	
	F13 = 1
	for cookie in cj:
		#print cookie.domain
		if(cookie.domain[:1] == "."):
			cookie.domain = cookie.domain[1:]
		domainCookie = getDomain(cookie.domain)

		if(domainLink != domainCookie):
			F13 = -1
			return F13
			
	return F13
		
#Fitur 14 - SSL Certificate
def cekSSL(link):
	if(link[:5] == "https"):
		try:
			requests.get(link, verify = True)
			F14 = 1
		except:
			F14 = -1
	else:
		F14 = -1
		
	return F14

#Fitur 15 - Search Engine 
def cekGoogle(link):
	apiKey = "AIzaSyDoDnAsM5XSi5IAsVRw_PyV8S7tazEJVhE"
	cx = "015058113956565325925"
	q = link
	
	headers = {'User-Agent':'Mozilla/5.1'}
	request = urllib2.Request("https://www.googleapis.com/customsearch/v1?key=" + apiKey + "&cx=" + cx + ":awgpmf5zb5k&q=" + q, headers = headers)
	response = urllib2.urlopen(request)
	data = json.load(response)
	
	domainPA = getDomain(getPath(link))
		
	result = data["items"]
	counter = 5
	i = 0
	for h in result: 
		url = h["link"]
		domainSearch = getDomain(getPath(url))
		print domainSearch
		if(domainSearch == domainPA):
			counter -= 1
		
		i += 1
		if(i == 5):
			if(counter == 0):
				return 1
			else:
				return -1
	
	return -1
		
#Fitur 16 - Whois Lookup
def cekWhois(url):
	try:
		w = whois.whois(url)
		print w
		F16 = 1
	except:
		F16 = -1
		
	return F16

#Fitur 17 - Blacklist
def cekBlacklist(url):
	apiKey = "AIzaSyDb1Svuk9G9QkHJapw8V3C_iCYC9CF0ATM"
	url = ("https://sb-ssl.google.com/safebrowsing/api/lookup?client=TAPhishing&key=%s&appver=1.5.2&pver=3.1&url=%s" % (apiKey, url))
	tmp = urllib2.urlopen(url).read()
		
	if(tmp == "phishing" or tmp == "malware"):
		F17 = -1
	else:
		F17 = 1
		
	return F17
		
if __name__ == '__main__' :
	file = r"C:\Users\arie\arie\Dropbox\[ TUGAS AKHIR ] ARIE PRIYAMBADHA - 5110100100\Program\dataset\datasetFix.txt"
	hasilEkstraksi = open(r"hasilEkstraksi.txt", "w")
	bad = open(r"bad.txt", "w")
	
	with open(file, "r") as f:
		data = f.readlines()
	
	#connProxy() # Untuk Proxy ITS
	#connProxy() # Untuk Proxy2 ITS

	i = 0
	while i < 200:
		try:
                        print cekWhois(data[i])
		except:
			print "Gagal"
			
		i += 1

	print "Finished !!!"
	
