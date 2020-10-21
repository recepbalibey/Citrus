import gevent.monkey
gevent.monkey.patch_all()
import requests
import grequests
import json
import logging
import os
import threading 
import pprint
import random
from threading import Thread
import datetime
import numpy as np
import time

import matplotlib.pyplot as plt
from statsmodels.tsa.stattools import adfuller
from statsmodels.tsa.arima_model import ARMA, ARIMA, ARMAResults, ARIMAResults
from statsmodels.tools.eval_measures import rmse
from pmdarima import auto_arima
import pandas as pd
from msticpy.sectools import IoCExtract
import sys
sys.path.insert(0, './providers')
from .providers.virustotal import VirusTotal
from .providers.zoomeye import ZoomEye
from .providers.otx import OTX
from .providers.shodan import Shodan
from .providers.censys import Censys
from .providers.greynoise import Greynoise
from .providers.abuseipdb import AbuseIPDB
from .providers.apility import Apility
from .providers.hybridanalysis import HybridAnalysis
from .providers.maltiverse import Maltiverse
from .providers.asn import ASN

sys.path.insert(0, '/../citrus_lib')
from citrus_lib.host import *

class Intelligence():

    def __init__(self, hosts, _southbound):
        self.log = logging.getLogger('intel')
        self.hosts = hosts
        self.loadConfig()
        self._southbound = _southbound
        self._virus = VirusTotal()
        self._zoom = ZoomEye(self.config['feeds']['zoomeye']['username'], self.config['feeds']['zoomeye']['password'], self.hosts)
        self._censys = Censys(self.config['feeds']['censys']['uid'], self.config['feeds']['censys']['secret'], self.hosts)
        self._shodan = Shodan(self.config['feeds']['shodan']['key'], self.hosts)
        self._grey = Greynoise(self.config['feeds']['grey']['key'], hosts)
        self._otx = OTX(self.config['feeds']['otx']['key'])
        self._abuse = AbuseIPDB(self.config['feeds']['abuseipdb']['key'])
        self._apility = Apility(self.config['feeds']['apility']['key'], self.hosts)
        self._asn = ASN(self.hosts)
        self._hybrid = HybridAnalysis(self.config['feeds']['hybridanalysis']['key'], self.hosts)
        self._maltiverse = Maltiverse(self.config['feeds']['maltiverse']['email'], self.config['feeds']['maltiverse']['password'], self.hosts)
        self.load_feeds(self.config['modules']['tangerine']['mode'])
        self.ioc_extract = IoCExtract()
        self.req_limit = self.config['modules']['tangerine']['req_limit']
    
    def load_feeds(self, mode):
        if mode == "graph":
            self.feeds = [ self._apility,  self._censys, self._shodan, self._asn, self._hybrid, self._maltiverse]
        elif mode == "forecast":
            self.feeds = [ self._otx, self._apility, self._abuse, self._grey, self._asn ]

    def loadConfig(self):
        self.config_path = os.path.dirname(os.path.realpath(__file__)) + "/../config.json"
        with open(self.config_path) as data_file:    
            self.config = json.load(data_file)


    def get_feeds(self):
        return self.feeds

    def lookup_iocs(self, iocs):
        
        #NEED TO FIX EXTRACT IOC
       # ioc_df = self.ioc_extract.extract_df(iocs, columns=['src_ip'])
        print("Converting to numpy list...")
        ioc_list = iocs.to_numpy().tolist()
        ioc_list = [["ipv4", ioc[0]] for ioc in ioc_list]

        print("Getting requests object for each host...")
        _requests = []
        for feed in self.get_feeds(): #Loop through each intel provider
                                                        #[:100]
                _allowed = [[res[0], res[1]] for res in ioc_list[:self.req_limit] if res[0] in feed._IOC_QUERIES] #Get supported IoCs for feed

                if _allowed:
                    print(f"doing {feed.__str__}")
                    query_result = feed.g_query(_allowed)
                    for res in query_result:

                        _requests.append(res) 

        print("Shuffling requests...")
        #Shuffle list of requests (try to bypass certain limits of API consumption)
        random.shuffle(_requests)
        size = self.config['modules']['tangerine']['pool_size']
        print("Starting lookup...")
        return self._southbound._intel.sendRequests(_requests, size)

    def parse_intel(self, intel_list, mode):
        print("Starting intelligence parsing...")
        _time_series = []
        #Parse each response via feed .parse() method
        for k, v in intel_list.items():

            _host = self.hosts.getHost(intel_list[k]['ioc'])
            if _host is None:
                _host = self.hosts.addHost(intel_list[k]['ioc'])

            for feed in self.get_feeds():
                
                if v['provider'] == str(feed):
                    
                    parsed = feed.parse(intel_list[k])
                    
                    if parsed['type'] != 'apility' and parsed['data']:
                        
                        #_time_series.append(feed.get_ts(parsed))
                        
                        #print("ADDING: " + parsed['type'] + "from feed : " + feed.__str__())
                        if mode == 'forecast':
                            _host.addEntity(feed.get_ts(parsed), feed.__str__())
                        else:
                            _host.addEntity(feed.get_blacklists(parsed), feed.__str__(), blacklist=True)

                    elif parsed['type'] == 'apility' and parsed['data']: #Need to check item count, contain 200 items per apility request

                        currentLength = parsed['length']
                        data_dict = parsed['data']
                        currentPage = 2
                        #Limit of page reached
                        while currentLength == 200:
                           # print("Current Length : " + str(currentLength)) #Need to send request for page # + 1
                            
                            ioc_arr = [intel_list[k]['ioc_type'], intel_list[k]['ioc']]
                            r = feed.query(ioc_arr, currentPage)
                            p = feed.parse(r)
                            currentLength = p['length']
                            currentPage = currentPage + 1
                            if p['data']:
                                data_dict.update(p['data'])

                        if mode == 'forecast':
                            _host.addEntity(feed.get_ts(data_dict), feed.__str__())
                        else:
                            _host.addEntity(feed.get_blacklists(data_dict), feed.__str__(), blacklist=True)
                        #print("ADDING: " + parsed['type'] + "from feed : " + feed.__str__())

        self._hybrid.query()

