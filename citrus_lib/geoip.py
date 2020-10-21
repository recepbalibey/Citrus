import geoip2.database

class GeoIP():

    def __init__(self, path):
        self.path = path

    def read(self, ip):
        
        try:
            with geoip2.database.Reader(self.path) as reader:
                response = reader.asn(ip)
                return response.autonomous_system_number
        except:
            return None



    def addDefaultASN(self, hosts):

        for ip, host in hosts.items():
            if host.asn is None:

                asn = self.read(ip)
                if asn is not None:
                    host.asn = asn
    
    def getASN(self, ip):
        return self.read(ip)