from .entity import Entity

class Blacklist(Entity):

    def __init__(self, name):

        self.name = name
        self.associated_ips = []

    def addIP(self, ip):
        self.associated_ips.append(ip)

    def getIPs(self):
        return self.associated_ips
