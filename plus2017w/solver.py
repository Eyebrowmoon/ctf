#!/usr/bin/python

import sys

text1 = 'ZbZbCbDbKKn2W3XiQ1CiV4FcJBp988ugzpl39lqpYceedbDYIO32SwH3QXDwR9h0VcpN8=pf3Ky7z5g='
text2 = 'ZYbdYbYLICIZcYPIIPYJIIDDcbZKPIKCn32HWGSGHiCXmSSCGTyiCGQQmmSizCTgVR4J5UxMsABR4ABYI0ABEMppldgA8os=upgpnoipNgy1g9imggmh9790hsv//vN='
text3 = 'ZWhNcChzPTJgn5zCmspbTslPVjbi4rZ20NYzuc2AgI2hgCX8YmhgKCgpcnNg3VpIHEpZ20pKRhZCN9I29Nbipc2BvPCgoCm8b2gyaSYramcp2lpZGBmKWloO4uIXlzIyduLwgZHRnbCAoYy=ays1a2h9K3o='
text4 = 'Z4c9csZ9Pkc9D1d8ngljGNXjTg2jQlCgVc9YVCRY0JkYpXgKu2uWwi1WgigW92viYFbNcAcNcYIND9K83t3v2gmvGgTvQyipRZQbkI4bVc0bpXAOpVoGpCgGwGgGz2/wb9YEIBYEcVYEY5P=2v2sHy2g2w27Wvz='

interval = 16
linelen = len(text4) / interval

arr = []
for i in xrange(interval):
  line = ''
  for j in xrange(linelen):
    line += text4[interval * j + i]
  arr.append(line)

for line in arr:
  sys.stdout.write(line)
