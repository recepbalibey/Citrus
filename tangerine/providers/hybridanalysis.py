
from .feed import Feed
import requests
import grequests
import json
import sys
sys.path.insert(0, '/../../citrus_lib')
from citrus_lib.file import File

import pandas as pd
import time

class HybridAnalysis(Feed):

    def __init__(self, key, hosts):
        self.base_url = "https://www.hybrid-analysis.com/api/v2"
        self.key = key
        self.hosts = hosts
        self.type = 'hybrid'
        self._IOC_QUERIES = {
            "ipv4": "/search/terms",
            "sha256": "/report/summary"
        }

        self.headers = {

                    "accept": "application/json",
                    "user-agent": "Citrus",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "api-key": self.key
        }
        self.found = []
        super().__init__()

    def get_ts(self, data):
        pass


    
    def parse(self, response):

        if response['status_code'] != 200:
            return {"type": self.__str__(), "data": None, "response": response['status_code']}
        
        js = response['json']

        #print(json.dumps(js, indent= 4))

        res = js['result']

        if len(res) > 0:

            host = js['search_terms'][0]['value']
            for r in res:
                
                item = {"sha256": r['sha256'], "environment_id": r['environment_id'], "host": host}
                self.found.append(item)
                
                host = self.hosts.getHost(host)

                if host is not None:
                    file = File(r['sha256'])
                    host.addFile(file)

        return {"type": self.__str__(), "data": None, "response": response['status_code']}

    def g_query(self, ioc: ["ioc_type", "ioc"]):

        rs = []

        for res in ioc:
            url = self.base_url + self._IOC_QUERIES[res[0]]
            data = f"host={res[1]}"
            rs.append(grequests.post(url, timeout=30, headers=self.headers, data=data, hooks={'response': self.hook_factory(ioc=res)}))

        return rs

    def query(self):

        url = self.base_url + self._IOC_QUERIES["sha256"]
        temp = ""
        first = True

        #Hybrid Analysis limits to 100 hashes per post
        i = 0

        print(f"Found hashes - {self.found}")
        for f in self.found:

            if i > 5:

                try:
                    r = requests.post(url, headers=self.headers, data=temp)

                  #  print(temp)
                 #   print(r.text)
                    js = r.json()
                    self.addIPs(js)
                    temp = ""
                    i = 0
                    first = True
                
                except:
                  #  print(temp)
                 #   print(r.text)
                    temp = ""
                    i = 0
                    first = True



            if first:
                first = False
                temp = f"hashes[]={f['sha256']}:{f['environment_id']}"

                i = i + 1
                continue

            temp = temp + f"&hashes[]={f['sha256']}:{f['environment_id']}"
            i = i + 1

            time.sleep(1)


        try:

          #  print(temp)
            r = requests.post(url, headers=self.headers, data=temp)

            js = r.json()
        #    print(js)

            self.addIPs(js)
        
        except:

           # print(temp)
            print(r.text)
        
        #print(json.dumps(js, indent= 4))
        
    def addIPs(self, js):
        for res in js:
        #    print(js)
         #   print(res)
            if 'sha256' in res and 'hosts' in res:

                sha256 = res['sha256']
                hosts = res['hosts']
             #   print(f"This file has {len(hosts)} contacted hosts")
                #Something definately wrong with this
                for host in hosts:
       
                    if host in self.hosts.getHosts():
                #        print(f"Found {host} in hosts")
                        for sha, file in self.hosts.getHosts()[host].getFiles().items():
                            if sha == sha256:
                            #     print("Adding contacted IP")
                                file.addContactedIPs(hosts)

        

    def __str__(self):
        return "hybrid"

