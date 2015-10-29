#get domain name from raw url
def getDomainName(url):
    indexDoubleSlash = url.find("/") + 1
    subUrl = url[indexDoubleSlash + 1:]
    if "/" in subUrl:
        domainName = subUrl[:subUrl.find("/")]
    else:
        domainName = subUrl

    return domainName


#fake user agents
headers = {"User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1"}

#get database
with open("dataset.txt", "r") as file:
    data = file.readlines()

n = 0
while n < len(data):