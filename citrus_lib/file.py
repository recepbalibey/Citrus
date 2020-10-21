from .entity import Entity
class File(Entity):

    def __init__(self, sha256):

        self.sha256 = sha256
        self.contacted = []

    def addContactedIPs(self, ip):
        self.contacted = ip

    def getContactedIPs(self):
        return self.contacted

    def getSHA256(self):
        return self.sha256