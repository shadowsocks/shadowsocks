#!/usr/bin/env python

import sys
import socket
import bisect

def ip2int(ip):
    return reduce(lambda x,y: x*256+y, [int(x) for x in ip.split('.')])

def init_geolite():
    import urllib2
    import zipfile
    import StringIO
    buf = StringIO.StringIO(urllib2.urlopen("http://geolite.maxmind.com/download/geoip/database/GeoIPCountryCSV.zip").read())
    geolite_begin = []
    geolite_end = []
    for line in zipfile.ZipFile(buf).open('GeoIPCountryWhois.csv').readlines():
        ip_begin, ip_end, int_begin, int_end, code = line.strip().split(',')[0:5] 
        if code == '"CN"':
            geolite_begin.append(int(int_begin[1:-1]))
            geolite_end.append(int(int_end[1:-1]))
    for ip_begin, ip_end in internal_ip:
        ipb = ip2int(ip_begin)
        ipe = ip2int(ip_end)
        i = bisect.bisect(geolite_begin, ipb)
        geolite_begin.insert(i, ipb)
        geolite_end.insert(i, ipe)
    return (geolite_begin, geolite_end)

def ischina(ip_int):
    if geolite:
        i = bisect.bisect_right(geolite[0], ip_int) -1
        if i == 0 or ip_int > geolite[1][i]:
            return False
        else:
            return True
    else:
        return False

def isdirect(hostname):
    hostname = hostname.strip()
    try:
        ip = socket.gethostbyname(hostname)
    except Exception, e:
        ip = "0.0.0.0"
    ip_int = ip2int(ip)
    try:
        is_china = ischina(ip_int)
    except Exception, e:
        is_china = False

    return  is_china and \
            (ip_int not in blacklist_ip) and \
            (not any([hostname.endswith(i) for i in blacklist_domain])) \
            or \
            (any([hostname.endswith(i) for i in whitelist_domain]))

#bad IPs returned by domestic DNS servers
blacklist_ip =[ip2int(ip) for ip in ['60.191.124.236', '180.168.41.175', '93.46.8.89', '203.98.7.65', '8.7.198.45', '78.16.49.15', '46.82.174.68', '243.185.187.39', '243.185.187.30', '159.106.121.75', '37.61.54.158', '159.24.3.173', '0.0.0.0']]
#domains hijacked
blacklist_domain = ['skype.com', 'youtube.com']
#private IP ranges
internal_ip = [("127.0.0.0", "127.255.255.255"), ("192.168.0.0", "192.168.255.255"), ("172.16.0.0", "172.31.255.255"), ("10.0.0.0", "10.255.255.255")]
#private domain names
whitelist_domain = ['local', 'localhost' ]

geolite = init_geolite()

if __name__ == "__main__":
    while 1:
        line=sys.stdin.readline()
        if line == "":
            break
        print("OK" if isdirect(line) else "ERR")
        sys.stdout.flush()
