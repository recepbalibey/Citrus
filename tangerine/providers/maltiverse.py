
from .feed import Feed
import requests
import grequests
import json
import sys
sys.path.insert(0, '/../citrus_lib')
from citrus_lib.file import File
import pandas as pd
from threading import Thread
import time

class Maltiverse(Feed):

    def __init__(self, username, password, hosts):
        self.base_url = "https://api.maltiverse.com"
        self.username = username
        self.password = password
        self.hosts = hosts
        self.type = 'maltiverse'
        
        self._IOC_QUERIES = {
            "ipv4": "/bulk/ip",
            
        }

        self.token = ""
        self.headers = {

                    "Accept": "application/json, text/plain, */*",
                    "Content-Type": "application/json",
                    "Connection": "keep-alive"

        }

        thread = Thread(target=self.getHeader, args=(self.username, self.password))
        thread.start()
        super().__init__()
          

    def getHeader(self, user, password):

        
        data = {"email": user, "password": password}
        data = json.dumps(data)
        auth_url = self.base_url + "/auth/login"
        
        try:  
            r = requests.post(auth_url, data=data, headers=self.headers)
            if r and r.status_code == 200 and 'auth_token' in r.json():
                token = r.json().get('auth_token')
                self.token = token
                self.headers['Authorization'] = 'Bearer %s' % self.token
                print("Succesfully set Malt header")
            else:
                req = r.request

                command = "curl -X {method} -H {headers} -d '{data}' '{uri}'"
                method = req.method
                uri = req.url
                data = req.body
                headers = ['"{0}: {1}"'.format(k, v) for k, v in req.headers.items()]
                headers = " -H ".join(headers)
                print("Maltiverse Header ERROR")
                print(command.format(method=method, headers=headers, data=data, uri=uri))


        except Exception as e:
            print(e)

    def get_ts(self, data):
        pass

    def parse(self, response):

        if response['status_code'] != 200:

            js = response['json']
            print(json.dumps(js, indent= 4))

            return {"type": self.__str__(), "data": None, "response": response['status_code']}
        
        js = response['json']

       # print(json.dumps(js, indent= 4))
       # print(f"malti {js}")
        
        if 'ip_addr' in js:
               
            for report in js['ip_addr']:
                
                ip = report['ip_addr']
                classification = report['classification']
                if classification == "whitelist":
                    continue
                

                if 'blacklist' in report and len(report['blacklist']) > 0:
                    _bl_dic = {}
                  #  print(f"adding blacklists to host {report['blacklist']}")
                    for bl in report['blacklist']:
                        _bl_dic[bl['source']] = bl
                        host = self.hosts.getHost(ip)
                        host.malti_blacklist = _bl_dic



     #   print("ip_addr not in js")
        return {"type": self.__str__(), "data": None, "response": response['status_code']}

    def g_query(self, ioc: ["ioc_type", "ioc"]):

        rs = []


        ip_dic = {}
        ip_dic['ip_addr'] = []
        while self.token == '':
            time.sleep(1)
    
        counter = 0
        for res in ioc:
            
            if counter > 100:
                
                data = json.dumps(ip_dic)
                url = self.base_url + self._IOC_QUERIES[res[0]]
                rs.append(grequests.post(url, timeout=30, headers=self.headers, data=data, hooks={'response': self.hook_factory(ioc=res)}))
                ip_dic = {}
                ip_dic['ip_addr'] = []
                counter = 0

            ip_dic['ip_addr'].append(res[1])
            counter = counter + 1
            
        data = json.dumps(ip_dic)

        print(data)

        url = self.base_url + self._IOC_QUERIES[res[0]]

        rs.append(grequests.post(url, timeout=30, headers=self.headers, data=data, hooks={'response': self.hook_factory(ioc=res)}))

        
        return rs

    def query(self):
        pass

        

    def __str__(self):
        return "maltiverse"

