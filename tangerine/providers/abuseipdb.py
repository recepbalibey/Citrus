from threading import Thread
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

class AbuseIPDB(Feed):

    def __init__(self, key):

        super().__init__()

        self.base_url = 'https://api.abuseipdb.com'
        self.key = key
        self._IOC_QUERIES = {
            "ipv4": "/api/v2/check",
        }

        self.headers = {
            'Accept': 'application/json',
            'Key': self.key
        }

        self.type = "abuseipdb"

       
    def __str__(self):
        return "abuseipdb"
    

    #Returns no. of reports per day

    def get_ts(self, data):

        data = data['data']
        index = pd.DatetimeIndex(data).rename("Date")
        data = pd.Series(1, index=index).to_frame()
        count_per_day = data.resample('D').sum()
        count_per_day = count_per_day.rename({0: self.type}, axis=1)
       # print("PARSING ABUSE")
       # print(count_per_day)
        return count_per_day

    #Return array of each time report made within DB
    #Format 2018-12-20T20:55:14
    def parse(self, response):

        #Server sometimes error code 500 
        if response['status_code'] != 200:
            ret = {"type": self.__str__(), "data": None, "response": response['status_code']}

        json = response['json']['data']
        
        if 'reports' in json and len(json['reports']) > 0:

            reports = [report['reportedAt'].split("+")[0] for report in json['reports']]
            ret = {"type": self.__str__(), "data": reports}
            return ret
        else:
            return {"type": self.__str__(), "data": None}


    def g_query(self, ioc: ["ioc_type", "ioc"]):

        rs = []
        
        for res in ioc:

            qs = {

                'ipAddress': res[1],
                'maxAgeInDays': '365',
                'verbose': True
            
            }
            url = self.base_url + self._IOC_QUERIES[res[0]]
            rs.append(grequests.get(url, timeout=30, headers=self.headers, params=qs, hooks={'response': self.hook_factory(ioc=res)}))

        return rs