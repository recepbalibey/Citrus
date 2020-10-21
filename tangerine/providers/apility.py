from .feed import Feed
import time
import requests
import grequests
import json
import matplotlib.pyplot as plt
from statsmodels.tsa.stattools import adfuller
from statsmodels.tsa.arima_model import ARMA, ARIMA, ARMAResults, ARIMAResults
from statsmodels.tools.eval_measures import rmse
from pmdarima import auto_arima
import pandas as pd
from datetime import datetime
import numpy as np
class Apility(Feed):

    def __init__(self, key, hosts):

        super().__init__()

        self.base_url = 'https://api.apility.net'
        self.key = key
        self.type = 'apility'
        self._IOC_QUERIES = {
            "ipv4": "/metadata/changes/ip/{observable}",
        }
        self.hosts = hosts
        self.headers = {
            'Accept': 'application/json',
            'X-Auth-Token': self.key
        }
         
    #Need to change so that each day in dict has list of blacklists it is in at end of day
    def get_blacklists(self, data):

        dic = {}
        dates = []
        _changes = []
   #     print(len(data))

        for _, v in data.items():

            date = datetime.fromtimestamp(v['timestamp'] / 1000.0)
            
            dates.append(date)
            dic[date] = v

        dates = sorted(dates)
        for date in dates:

            _blacklists = dic[date]['blacklists']
            if len(_blacklists) > 0:
                _changes.append(_blacklists)
            else:
                _changes.append("None")


        index = pd.DatetimeIndex(dates).rename("Date")
        data = pd.Series(_changes, index=index).to_frame()
        data = data.resample('D').last().dropna()
        #data = data.rename({0: self.type}, axis=1)
     #   print("Adding apility blacklist data")
        return data


    #SOME KIND OF BUG MAKES NEGATIVE  & Doesn't go all to end
    def get_ts(self, data):

        #print(data['data'])
        dic = {}
        dates = []
     #   print(len(data))

        #CAN DO IN 1 LOOP - FIX LATER
        for _, v in data.items():
            #print(v)
            date = datetime.fromtimestamp(v['timestamp'] / 1000.0)
            dates.append(date)
            dic[date] = v

        dates = sorted(dates)

        _num = 0
        _changes = []
        for date in dates:

            if dic[date]['command'] == 'add':
                _num = _num + 1
            else:
                _num = _num - 1
            
            _changes.append(_num)

        index = pd.DatetimeIndex(dates).rename("Date")
        data = pd.Series(_changes, index=index).to_frame()
        count_per_day = data.resample('D').mean().replace(np.nan, 0)
        count_per_day = count_per_day.rename({0: self.type}, axis=1)

        #print(count_per_day)
        #print(dates)
        return count_per_day

    def parse(self, response):
        
        if response['status_code'] != 200:
            return {"type": self.__str__(), "data": None, "length": 0, "response": response.status_code}


        json = response['json']
        #print(response['json'])
        _dict = {}
        
        if 'changes_ip' in json and len(json['changes_ip']) > 0:
            
            activity_length = len(json['changes_ip'])
            for action in json['changes_ip']:
                #print(action)
                _dict[action['timestamp']] = action
            ret = {"type": self.__str__(), "data": _dict, "length": activity_length}
            return ret

        else:
            return {"type": self.__str__(), "data": None, "length": 0}

    def g_query(self, ioc: ["ioc_type", "ioc"]):

        rs = []
        
        for res in ioc:

            url = self.base_url + self._IOC_QUERIES[res[0]].format(observable=res[1])
            rs.append(grequests.get(url, timeout=30, headers=self.headers, params={'items': 200, "page": 1}, hooks={'response': self.hook_factory(ioc=res)}))

        return rs
       
    def __str__(self):
        return "apility"

    def query(self, ioc:["ioc_type", "ioc"], currentPage):
        url = self.base_url + self._IOC_QUERIES[ioc[0]].format(observable=ioc[1])
        r = requests.get(url, headers=self.headers, params={"items":200, "page": currentPage})
        #NEED TO FIX RATE LIMITING
        return {"json": r.json() if r.status_code == 200 else r.text, "status_code": r.status_code}