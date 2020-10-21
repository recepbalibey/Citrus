import grequests

class IntelCollector:
    
    def __init__(self):
        pass
    
    def sendRequests(self, _requests, size):

        #Size parameter limits/throttles number of pools (threads) grequests opens at once
        responses = (grequests.map(_requests, size=size))

        intel_list = {}
        for r in responses:
            if r:

                try:
                    intel_list[r.ioc[1] + "_" + r.type] = {"json": r.json(), "ioc" : r.ioc[1], "ioc_type": r.ioc[0], "status_code": r.status_code, "provider": r.type}
                except:
                    print(f"{r.type} has given non-json response | Code {r.status_code}")
                    req = r.request

                    command = "curl -X {method} -H {headers} -d '{data}' '{uri}'"
                    method = req.method
                    uri = req.url
                    data = req.body
                    headers = ['"{0}: {1}"'.format(k, v) for k, v in req.headers.items()]
                    headers = " -H ".join(headers)
                    print("Maltiverse Header ERROR")
                    print(command.format(method=method, headers=headers, data=data, uri=uri))

        
        return intel_list