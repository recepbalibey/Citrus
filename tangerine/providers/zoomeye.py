from threading import Thread
from .feed import Feed
import time
import requests
import grequests
import json
import sys
sys.path.insert(0, '/../citrus_lib')
from citrus_lib.service import Service
from citrus_lib.host import *

class ZoomEye(Feed):

    def __init__(self, user, password, hosts):
        super().__init__()

        self.base_url = 'https://api.zoomeye.org'
        self.login_url = 'https://api.zoomeye.org/user/login'
        self.query_url = 'https://api.zoomeye.org/host/search?query='
        self.token = ''
        self._IOC_QUERIES = {
            "ipv4": "/host/search?query={observable}",
        }
        self.hosts = hosts
        thread = Thread(target=self.getHeader, args=(user, password))
        thread.start()



       
    def __str__(self):
        return "zoomeye"

    def getHeader(self, user, password):
        
        data = {"username": user, "password": password}
        data = json.dumps(data)
        try:  
            r = requests.post(self.login_url, data=data)
            if r and r.status_code == 200 and 'access_token' in r.json():
                token = r.json().get('access_token')
                self.token = token
                self.headers = {'Authorization': 'JWT %s' % self.token}
                #print(self.headers)
        except Exception as e:
            print(e)

    def get_ts(self, data):
        pass            

    def parse(self, response):

        if response['status_code'] != 200:
            return {"type": self.__str__(), "data": None, "response": response['status_code']}

        json = response['json']
        try:

            if len(json['matches']) > 0: #ENTRYPOINT

                services = []
                for match in json['matches']:
                    ip  = match['ip']
                    if 'portinfo' in match:
                        portinfo = match['portinfo']

                        s = Service(portinfo['port'], portinfo['service'], portinfo['version'], portinfo['banner'], portinfo['app'], self.__str__(), match['timestamp'])
                        services.append(s)

                host = self.hosts.getHost(ip)
                host.addServices(services)


                return {"type": self.__str__(), "data": None}
            else: 
                return {"type": self.__str__(), "data": None}

        except:
            return {"type": self.__str__(), "data": None}



    def g_query(self, ioc: ["ioc_type", "ioc"]):
        rs = []
        while self.token == '':
            print("token not reg - sleepin")
            time.sleep(1)
            
        for res in ioc:
            url = self.base_url + self._IOC_QUERIES[res[0]].format(observable=res[1])
            rs.append(grequests.get(url, timeout=30, headers=self.headers, hooks={'response': self.hook_factory(ioc=res)}))

        return rs

    def query(self, ioc_type, ioc):

        while self.token == '':
            print("token not reg - sleepin")
            time.sleep(1)

        try:
            if ioc_type in self._IOC_QUERIES:
            #url = self.query_url + "ip:" + ip
                url = self.query_url + ioc
                r = requests.get(url, headers=self.headers)
                if r.status_code == 200:
                    js = r.json()
                    js['type'] = 'zoomeye_' + ioc_type
                    js['ioc'] = ioc
                    js['code'] = r.status_code
                    return js
                else:
                    js = {'type': 'zoomeye_' + ioc_type, 'code': response.status_code, 'ioc': ioc}
                    return js
        except:
            
            print("cannot query zoomeye")
        