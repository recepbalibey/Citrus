
from .feed import Feed
import requests
import grequests
from dateutil.parser import parse as dateparse
import pandas as pd
import sys
sys.path.insert(0, '/../citrus_lib')
from citrus_lib.service  import Service

class Greynoise(Feed):
    def __init__(self, key, hosts):
        self.base_url = "https://api.greynoise.io/v2"
        self.type = 'grey'
        self.key = key
        self._IOC_QUERIES = {
            "ipv4": "/noise/context/{observable}",
        }
        self.hosts = hosts
        super().__init__()
 
    def __str__(self):
        return "greynoise"


    def get_ts(self, data):


        data = data['data']
        firstDate = dateparse(data['firstSeen'])
        lastDate = dateparse(data['lastSeen'])

        dates = [firstDate, lastDate]
        index = pd.DatetimeIndex(dates).rename("Date")
        ts = pd.Series(1, index=index).to_frame()
        return ts


    def g_query(self, ioc: ["ioc_type", "ioc"]):
        rs = []

        for res in ioc:
            url = self.base_url + self._IOC_QUERIES[res[0]].format(observable=res[1])
            rs.append(grequests.get(url, timeout=30, headers={'key': self.key}, hooks={'response': self.hook_factory(ioc=res)}))

        return rs

    def parse(self, response):

        if response['status_code'] != 200:
            return {"type": self.__str__(), "data": None}

        js = response['json']
        if 'seen' in js and js['seen'] == True:

            if 'raw_data' in js:
                if 'scan' in js['raw_data']:

                    services = []
                    for service in js['raw_data']['scan']:
                        _port = service['port']
                        _proto = service['protocol']
                        s = Service(_port, None, None, None, None, self.__str__(), js['last_seen'], _proto)
                        services.append(s)

                    host = self.hosts.getHost(js['ip'])
                    host.addServices(services)
                    
            if 'classification' in js:

                if js['classification'] == 'malicious':
                    dic = {"firstSeen": js['first_seen'], "lastSeen": js['last_seen']}
                    return {"type": self.__str__(), "data": dic}

        return {"type": self.__str__(), "data": None}
        #print(response)

    # [is_mal | geoip | services]
    def array_query(self, ip):
        if not ip:
            return [0,0,0]

        url = self.url + ip
        r = requests.get(url, headers={'key': self.key}) 
        if r and r.status_code == 200:
            a = r.json()
            malicious = 0
            if 'classification' in a and a['classification'] == 'malicious':
                malicious = 1
            else:
                malicious = 0

            meta_arr = []

            if 'metadata' in a:

                for _, value in a['metadata'].items():
                    meta_arr.append(value)
            else:
                meta_arr.append(0)

            services_arr = []
            
            if 'raw_data' in a and 'scan' in a['raw_data']:
                for i in a['raw_data']['scan']:
                    services_arr.append(i['port'])
            else:
                services_arr.append(0)
            return [malicious, meta_arr, services_arr]

        return [0,[0],[0]]

    def query(self, ioc_type, ioc):


        if not ioc:
            return {'type': 'grey', 'ip':'none'}

        if ioc_type in self._IOC_QUERIES:

            url = self.base_url + self._IOC_QUERIES[ioc_type].format(observable=ioc)
            r = requests.get(url, headers={'key': self.key})  
            if r and r.status_code == 200:
                a = r.json()
                a['type'] = self.type
                a['code'] = a.status_code
                a['ioc'] = ioc
                return a

           
            

            else:

                res = {'type': 'grey', 'code': r.status_code}
                return res
         
