import sys

from .feed import Feed
import requests
import grequests

class VirusTotal(Feed):


    def __init__(self):
        self.key = '', 
        self.headers = { "Accept-Encoding": "gzip, deflate", "User-Agent" : "gzip,  ding_dong"}
        self.base_url = 'https://www.virustotal.com/api/v3'
        self._IOC_QUERIES = {
            "ipv4": "/ip_addresses/{observable}",
            "hostname": "/domain/{observable}",
            "file_hash": "/files/{observable}",
            "url": "/url/{observable}",
        }
        super().__init__()

    def __str__(self):
        return "virustotal"

    def g_query(self, ioc: ["ioc_type", "ioc"]):
        
        rs = []

        for res in ioc:
            url = self.base_url + self._IOC_QUERIES[res[0]].format(observable=res[1])
            rs.append(grequests.get(url, timeout=30, headers={'x-apikey': str(self.key)}, hooks={'response': self.hook_factory(ioc=res)}))

        return rs
        
    def get_blacklists(self, data):
        pass
    def query(self, ioc_type, ioc):

        #params = {'apikey': self.key, 'resource': sha, 'allinfo':'true'}
        #self.log.info(params)

        if ioc_type in self._IOC_QUERIES:
            url = self.base_url + self._IOC_QUERIES[ioc_type].format(observable=ioc)
            res = requests.get(url, headers={'x-apikey': str(self.key)})
            if res.status_code == 200:
                js = res.json()
                js['type'] = 'virus_' + ioc_type
                js['ioc'] = ioc
                js['code'] = res.status_code
                return js
            else:
                js = {'type': 'virus_' + ioc_type, 'code': res.status_code, 'ioc': ioc}
                return js

    def get_ts(self, data):
        pass

    def parse(self, response):

        if response['status_code'] != 200:
            return {"type": self.__str__(), "data": None}
        return {"type": self.__str__(), "data": None}
        #print(response)

    def getUrlReport(self, url):
        params = {'apikey': self.key, 'resource': url}
        response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params, headers=self.headers) 
        json_response = response.json()
        json_response['type'] = 'virus'
        return json_response if json_response['response_code'] is not 0 else  None 

    def getDomainReport(self, url):
        params = {'apikey': self.key, 'domain': url}
        response = requests.get('https://www.virustotal.com/vtapi/v2/domain/report', params=params, headers=self.headers) 
        json_response = response.json()
        json_response['type'] = 'virus'
        return json_response if json_response['response_code'] is not 0 else  None 