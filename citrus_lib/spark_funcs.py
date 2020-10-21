import json
import hashlib
import datetime
from .config import Config
import os
import ipaddress
import geoip2.database
class SparkFunctions:

    def __init__(self, attackerIPsBroadcast):
        self.attackerIPsBroadcast = attackerIPsBroadcast

    def anon(self, ip):
        try:
            if ipaddress.ip_address(ip).is_global:
                reader = geoip2.database.Reader("/tmp/GeoLite2-ASN.mmdb")
                response = reader.asn(ip)
                return str(response.autonomous_system_number)

            else:
                return "786"
        except:
            return "786"

    def labelStream(self, src_ip, dest_ip):
        
        if src_ip in self.attackerIPsBroadcast.value or dest_ip in self.attackerIPsBroadcast.value:
           return "malicious"

        else:

            return "benign"

    def setDuration(self, time_start, time_end):
        if time_start is not None and time_end is not None:
            start_len = len(str(time_start))
            start_secs = time_start / 10 ** (start_len - 10)
            start_dt = datetime.datetime.fromtimestamp(start_secs)

            end_len = len(str(time_end))
            end_secs = time_end / 10 ** (end_len - 10)
            end_dt = datetime.datetime.fromtimestamp(end_secs)

            dif = end_dt - start_dt
            return str(dif.total_seconds())

    def fixTime(self, time):
        if time is not None:
            return time.replace(".", "")

    def ip_to_hostname(self, ip):
        try:
            qname = dns.reversename.from_address(ip)
            ans = str(dns.resolver.query(qname, 'PTR')[0])
            return ans
        except:
            return None

    def finalVerdict(self, src_col, dest_col, src_ip, dest_ip):

        whitelist = ["8.8.8.8"]
        if dest_ip in whitelist or src_ip in whitelist:
            return "benign"
            
        try:
            if ipaddress.ip_address(src_ip).is_private or ipaddress.ip_address(dest_ip).is_private:
                return 'benign'
        except:
            print("cant parse private ip")

        if src_col == 'malicious' or dest_col == 'malicious':
            return 'malicious'
        else:
            return 'outlier'

    def getLabel(self, ip, labels):
        return 1 if labels[ip]['verdict'] == 'malicious' else 0

    def process_rdd_for_save(self, row):
        resp = row['response']

        js = json.dumps(resp).encode('ascii', 'ignore')
        #resp['doc_id'] = hashlib.sha256(js).hexdigest()
        return (hashlib.sha256(js).hexdigest(), json.dumps(resp))
    
    def explode_grey(self, row):
        resp = row['response']
        #Just to give the Pyspark version of sgvd's answer. If the array column is in Col2, 
        # then this select statement will move the first nElements of each array in Col2 to their own columns:

        #From pyspark.sql import functions as F            
        #df.select([F.col('Col2').getItem(i) for i in range(nElements)])

        return [resp['ip'], resp['seen'], resp['classification'], resp['tags']]