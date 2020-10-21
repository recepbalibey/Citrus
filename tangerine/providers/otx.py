
from .feed import Feed
import requests
import grequests
import pandas as pd

class OTX(Feed):

    def __init__(self, key):
        self.base_url = "https://otx.alienvault.com"
        self.key = key
        self.type = 'otx'
        self._IOC_QUERIES = {
            "ipv4": "/api/v1/indicators/IPv4/{observable}/general",
            "ipv6": "/api/v1/indicators/IPv6/{observable}/general",
            "ipv4-passivedns": "/api/v1/indicators/IPv4/{observable}/passive_dns",
            "ipv6-passivedns": "/api/v1/indicators/IPv6/{observable}/passive_dns",
            "ipv4-geo": "/api/v1/indicators/IPv4/{observable}/geo",
            "ipv6-geo": "/api/v1/indicators/IPv6/{observable}/geo",
            "dns": "/api/v1/indicators/domain/{observable}/general",
            "dns-passivedns": "/api/v1/indicators/domain/{observable}/passive_dns",
            "dns-geo": "/api/v1/indicators/domain/{observable}/geo",
            "hostname": "/api/v1/indicators/hostname/{observable}/general",
            "file_hash": "/api/v1/indicators/file/{observable}/general",
            "url": "/api/v1/indicators/url/{observable}/general",
        }
        super().__init__()

    def get_ts(self, data):

        data = data['data']
        #print(data)

        #NEW WAY DELETE THIS IF DOESNT WORK
        data = [report['created'].split(".")[0] for report in data]
        
        index = pd.DatetimeIndex(data).rename("Date")
        data = pd.Series(1, index=index).to_frame()
        count_per_day = data.resample('D').sum()
        count_per_day = count_per_day.rename({0: self.type}, axis=1)


        return count_per_day

    def parse(self, response):

        if response['status_code'] != 200:
            return {"type": self.__str__(), "data": None, "response": response['status_code']}
        json = response['json']
        #pulses = json['pulse_info']['pulses']

        if len(json['pulse_info']['pulses']) > 0:
            #OLD WAY OF PARSING
           # pulses = [report['created'].split(".")[0] for report in json['pulse_info']['pulses']]
            pulses = [report for report in json['pulse_info']['pulses']]
            ret = {"type": self.__str__(), "data": pulses}
            return ret
        
        else:
            return {"type": self.__str__(), "data": None, "response": response['status_code']}
        #print(response)

    def g_query(self, ioc: ["ioc_type", "ioc"]):
        rs = []

        for res in ioc:
            url = self.base_url + self._IOC_QUERIES[res[0]].format(observable=res[1])
            rs.append(grequests.get(url, timeout=30, headers={'X-OTX-API-KEY': self.key}, hooks={'response': self.hook_factory(ioc=res)}))

        return rs

    def query(self, ioc_type, ioc):

        if ioc_type in self._IOC_QUERIES:

            url = self.base_url + self._IOC_QUERIES[ioc_type].format(observable=ioc)
            headers = {'X-OTX-API-KEY': self.key}
            r = requests.get(url, headers=headers)
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

            self.log.info("couldnt get otx status: " + str(r.status_code))

    def __str__(self):
        return "otx"

