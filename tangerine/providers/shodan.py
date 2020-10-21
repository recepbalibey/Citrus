from .feed import Feed
import requests
import sys
sys.path.insert(0, '/../citrus_lib')
from citrus_lib.service import Service
import grequests

class Shodan(Feed):

    def __init__(self, key, hosts):

        self.key = key
        super().__init__()
        self.base_url = 'https://api.shodan.io/shodan'
        self.type = 'shodan'
        self._IOC_QUERIES = {
            "ipv4": "/host/{observable}",
        }
        self.hosts = hosts

    def __str__(self):
        return self.type

    def parse(self, response):

        if response['status_code'] != 200:
            return {"type": self.__str__(), "data": None}

        json = response['json']
        if 'data' in json:

            services = []
            for service in json['data']:
                
                _service, _port, _vulns, _banner, _version, _protocol, _app, _timestamp = None, None, None, None, None, None, None, None

                if 'product' in service:
                    _app = service['product']

                if 'port' in service:
                    _port = service['port']

                if 'opts' in service and 'vulns' in service['opts']:
                    _vulns =  service['opts']['vulns']

                if 'data' in service:
                    _banner = service['data']
                
                if 'transport' in service:
                    _protocol = service['transport']

                if 'timestamp' in service:
                    _timestamp = service['timestamp']

                if 'smb' in service:
                    _service = 'smb'
                if 'ftp' in service:
                    _service = 'ftp'
                if 'http' in service:
                    _service = 'http'
                
                s = Service(_port, _service, _version, _banner, _app, self.__str__(), _timestamp, _protocol, _vulns)
                services.append(s)

            host = self.hosts.getHost(json['ip_str'])
            host.addServices(services)

        return {"type": self.__str__(), "data": None}

    def g_query(self, ioc: ["ioc_type", "ioc"]):
        rs = []

        for res in ioc:
            url = self.base_url + self._IOC_QUERIES[res[0]].format(observable=res[1])
            rs.append(grequests.get(url, timeout=30, params = {'key': self.key}, hooks={'response': self.hook_factory(ioc=res)}))

        return rs

    def get_ts(self, data):
        pass

    def query(self, ioc_type, ioc):

        if ioc_type in self._IOC_QUERIES:

            url = self.base_url + self._IOC_QUERIES[ioc_type].format(observable=ioc)
            params = {'key': self.key}
            r = requests.get(url, params=params)
            if r and r.status_code == 200:
                a = r.json()
                a['type'] = self.type
                a['ioc'] = ioc
                a['code'] = r.status_code
                return a
            else:
                js = {'type': self.type, 'code': r.status_code, 'ioc': ioc}
                return js

        else:

            self.log.info("couldnt get shodan status: " + str(r.status_code))
