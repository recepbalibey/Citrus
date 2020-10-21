
from .feed import Feed
import requests
import grequests
from dateutil.parser import parse as dateparse
import pandas as pd
from threading import Thread
import json
import time

class Cymon(Feed):
    def __init__(self, user, passwd):

        self.base_url = "https://api.cymon.io/v2/"
        self.type = 'grey'
        
        self._IOC_QUERIES = {
            "login": "/auth/login/",
            "ipv4": "/ioc/search/ip/{observable}"
        }

        super().__init__()
        thread = Thread(target=self.getHeader, args=(user, passwd))
        thread.start()



       
    def __str__(self):
        return "cymon"

    def g_query(self, ioc: ["ioc_type", "ioc"]):
        rs = []

        while self.token == '':
            time.sleep(1)

        for res in ioc:
            url = self.base_url + self._IOC_QUERIES[res[0]].format(observable=res[1])
            rs.append(grequests.get(url, timeout=30, headers=self.headers, hooks={'response': self.hook_factory(ioc=res)}))

        return rs

    def getHeader(self, user, password):
        
        data = {"username": user, "password": password}
        data = json.dumps(data)
        try:  
            r = requests.post(self.base_url + self._IOC_QUERIES['login'], data=data)
            if r and r.status_code == 200 and 'jwt' in r.json():
                token = r.json().get('jwt')
                self.token = token
                self.headers = {'Authorization': 'Bearer %s' % self.token}
                #print(self.headers)
        except Exception as e:
            print(e)