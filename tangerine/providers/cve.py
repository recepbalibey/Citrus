
import requests
import json
import datetime
import gzip
import os.path
import pandas as pd

class CVE():

    def __init__(self):
        self.base_url = "https://nvd.nist.gov/feeds/json/cve/1.1/"
        self.file = 'nvdcve-1.1-{year}.json.gz'

    def download(self, year):

        file = self.file.format(year=year)
        if not os.path.isfile('cve/' + file):
            url = self.base_url + self.file.format(year=year)
            r = requests.get(url)
            with open('cve/' + file, 'wb') as outfile:
                outfile.write(r.content)
            return self.file.format(year=year)

    def parse(self, year):
        
        if not os.path.isfile('cve/' + self.file.format(year=year)):
            self.download(year)
        
        f = gzip.open('cve/' + self.file.format(year=year))
        file_content = f.read()
        f.close()
        js = json.loads(file_content)

        date_arr = []
        for item in js['CVE_Items']:
        
            impact = item['impact']
            if 'baseMetricV2' in impact:
                if impact['baseMetricV2']['impactScore'] == 10 and impact['baseMetricV2']['exploitabilityScore'] == 10:
                    
                    date_arr.append(item['publishedDate'].split("T")[0])

        return set(date_arr)
            
    def get_ts(self, dates):
        
        dates = sorted(dates)
        index = pd.DatetimeIndex(dates).rename("Date")
        data = pd.Series("cve", index=index).to_frame()
        data.rename({0:"cve"}, axis=1)
        return data