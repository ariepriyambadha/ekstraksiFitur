def getDomainName(url):
    # Asumsi setiap url yang ada memiliki substring http://
    indexDoubleSlash = url.find("/") + 1
    subUrl = url[indexDoubleSlash + 1:]
    if "/" in subUrl:
        domainName = subUrl[:subUrl.find("/")]
    else:
        domainName = subUrl

    return domainName


headers = {"User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1"}

with open("dataset.txt", "r") as file:
    data = file.readlines()

n = 0
while n < len(data):

