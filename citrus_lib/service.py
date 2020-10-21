from dateutil.parser import parse as dateparse
from .entity import Entity

class Service(Entity):

    def __init__(self, port, service, version, banner, app, feed, timestamp, protocol=None, vuln=None):

        self.port = port
        self.service = service
        self.version = version
        self.banner  = banner
        self.app = app
        self.feed = feed
        self.timestamp = timestamp
        self.protocol = protocol
        self.vuln = vuln
        self.date = dateparse(timestamp)
    
    def getPort(self):
        return self.port

    def getService(self):
        return self.service

    def getVersion(self):
        return self.version

    def getBanner(self):
        return self.banner

    def getApp(self):
        return self.app
    
    def getFeed(self):
        return self.feed
    
    def getTimestamp(self):
        return self.timestamp

    def getDate(self):
        return self.date