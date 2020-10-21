
import requests
from .feed import Feed
import grequests
import sys
sys.path.insert(0, '/../citrus_lib')
from citrus_lib.service import Service

class Censys(Feed):

    def __init__(self, uid, secret, hosts):
        self.uid = uid
        self.secret = secret
        self.base_url = "https://censys.io/api/v1"
        self.type = 'censys'
        self._IOC_QUERIES = {
            "ipv4": "/view/ipv4/{observable}",
        }
        self.hosts = hosts
        super().__init__()

    def __str__(self):
        return self.type

    def get_ts(self, data):
        pass

    def parse(self, response):

        if response['status_code'] == 200:
            
            services = []
            json = response['json']

            if 'protocols' in json and len(json['protocols']) > 0:

                protos = json['protocols']
                ip = json['ip']
                for proto in protos:

                    split = proto.split("/")
                    _port = split[0]
                    _service = split[1]

                    service  = json[_port] #TODO Extract more info

                    s = Service(_port, _service, None, None, None, self.__str__(), json['updated_at'] if 'updated_at' in json else None)
                    services.append(s)

                    #print(f"CENSYS SERVICE ADDED : {_port} {_service}")

                host = self.hosts.getHost(ip)
                host.addServices(services)

            return {"type": self.__str__(), "data": None}

        return {"type": self.__str__(), "data": None}
        #print(response)

    def g_query(self, ioc: ["ioc_type", "ioc"]):
        rs = []

        for res in ioc:
            url = self.base_url + self._IOC_QUERIES[res[0]].format(observable=res[1])
            rs.append(grequests.get(url, timeout=30, auth=(self.uid, self.secret), hooks={'response': self.hook_factory(ioc=res)}))

        return rs

    def query(self, ioc_type, ioc):

        url = self.base_url + self._IOC_QUERIES[ioc_type].format(observable=ioc)
        r = requests.get(url, auth=(self.uid, self.secret))

        if r and r.status_code == 200:
            js = r.json()
            js['type'] = self.type
            js['ioc'] = ioc
            return js

        
        else:

            res = {'type': self.type, 'code': r.status_code, 'ioc': ioc}
            return res
        