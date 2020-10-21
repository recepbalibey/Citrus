import grequests
import json
import time
from .feed import Feed
import sys
sys.path.insert(0, '/../citrus_lib')
from citrus_lib.host import Host
import pandas as pd
import os
from dateutil.parser import parse as dateparse

class ASN(Feed):

    def __init__(self, hosts):
        self.base_url = "https://bgpranking-ng.circl.lu/ipasn_history/"
        self._cache = 'mass_cache'
        self._query = 'mass_query'
        self.type = 'asn'
        self._IOC_QUERIES = {
            "ipv4": "mass_cache",
        }
        self.hosts = hosts
        self.loadConfig()

    def loadConfig(self):
        self.config_path = os.path.dirname(os.path.realpath(__file__)) + "/../../config.json"
        with open(self.config_path) as data_file:    
            self.config = json.load(data_file)

    def parse_ts(self, dates, host):

        if host.getFirstDate() and host.getLastDate(): #Make sure intel has been gathered for host

            valid_dates = [date for date in dates if date > host.getFirstDate() and date < host.getLastDate()]
            if len(valid_dates) > 0:
                index = pd.DatetimeIndex(valid_dates).rename("Date")
                data = pd.Series(1, index=index).to_frame()
                host.asn_changes = data
                print('ASN for host has been added as TS - ' + host.ip)

    #If error in parsing most likely that query wasn't done correctly.
    def parse(self, js):

        js = js['json']
        if 'responses' in js and len(js['responses']) > 1:
            for res in js['responses']:

                ip = res['meta']['ip']
                host = self.hosts.getHost(ip)
                resp = res['response']
                first = True
                lastASN = None
                changes = []
                for k, v in resp.items():
                    if not 'asn' in v:
                        continue
                    if first:
                        #print(v)
                        lastASN = v['asn']
                        first = False
                        continue
                    
                    if v['asn'] != lastASN:
                        d = dateparse(k)
                        changes.append(d)
                        print("ASN HAS CHANGED - " + k)
                    
                    lastASN = v['asn']

                #TODO: Look into setting ASN of host to what it was on date communicating with HPot
                if len(changes) > 0:
                    self.parse_ts(changes, host)

                    host.asn = int(lastASN)

                else: 
                    if lastASN is not None:
                        
                        host.asn = int(lastASN)

        ret = {"type": self.__str__(), "data": None}
        return ret

    #If this isn't working switch to requests
    #Need to call cache b4 query
    def g_query(self, ioc: ["ioc_type", "ioc"], firstDate='2018-01-01'):
        
        _params = []
        rs = []
        for i in ioc:
            param = {'ip': i[1], 'first': firstDate}
            _params.append(param)
        
        #print(_params)
        rs.append(grequests.post(self.base_url + self._cache, timeout=30, data=json.dumps(_params), hooks={'response': self.hook_factory(ioc=['_cache', '_cache'])}))
        rs.append(grequests.post(self.base_url + self._query, timeout=30, data=json.dumps(_params), hooks={'response': self.hook_factory(ioc=['_query', '_query'])}))
        return rs
    
    def __str__(self):
        return self.type

