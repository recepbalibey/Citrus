import pandas as pd
import datetime
import numpy as np
import matplotlib.pyplot as plt
from statsmodels.tsa.api import VAR, VARMAX
from .helper import Helper
from statsmodels.tsa.stattools import adfuller
from statsmodels.tsa.arima_model import ARMA, ARIMA, ARMAResults, ARIMAResults
from statsmodels.tools.eval_measures import rmse
from pmdarima import auto_arima
from .models import Models
import functools

models = Models()

class Host():

    def __init__(self, ip, evalEngine):
        self.services = {}
        self.ip = ip
        self.good = False
        self.bad = False
        self.TS = []
        self.df = None
        self.asn_changes = None
        self.asn = None
        self.isMal = False
        self.em_result = False
        self.models = []
        self.evalEngine = evalEngine
        self.goodIPs = evalEngine.goodIPs
        self.badIPs = evalEngine.badIPs
        self.blacklist = None
        self.malti_blacklist = None
        self.files = {}

        if ip in self.goodIPs:
            self.good = True

        elif ip in self.badIPs:
            self.bad = True

        self.grey = None

    def addFile(self, file):
        self.files[file.getSHA256()] = file
        
    def getFiles(self):
        return self.files

    def addServices(self, services):

        for service in services:

            port = service.getPort() 

            if port in self.services:
                self.services[port].append(service)

            else:
                self.services[port] = [ service ]

    def isMalicious(self):
        #if greynoise == malicious and last seen when seen on honeypot
        return self.isMal 

    def applyModel(self, name):

        if name == "var" or name == "varma" or name == "mprophet":
            return models.apply(name, self.df, self)
        
        else:
            return models.apply(name, self.TS, self)


    def getMaltiverseBlacklistsByData(self, date):
        if self.malti_blacklist is not None:
            
            date = datetime.datetime.strptime(date, '%Y.%m.%d')
            active_bl = {}
            for name, info in self.malti_blacklist.items():

                _start_date = info['first_seen'].split(" ")[0]
                _end_date = info['last_seen'].split(" ")[0]
                start_date_obj = datetime.datetime.strptime(_start_date, '%Y-%m-%d')
                end_date_obj = datetime.datetime.strptime(_end_date, '%Y-%m-%d')

                if start_date_obj <= date and end_date_obj >= date:
                    active_bl[name] = info
            
            if len(active_bl) > 0:
                return active_bl


        
        return None

    def getBlacklistsByDate(self, date):

        for index in self.blacklist.index:
            
            _date = index.strftime("%Y.%m.%d")
            #Found exact match, return blacklists
            if _date == date:
                return self.blacklist.loc[_date.replace(".", "-")]
        
        #If no changes to blacklists on date, get blacklists from date previously changed

        _prev_df = self.blacklist.loc[:pd.Timestamp(date.replace(".", "-"))]
        if len(_prev_df) > 0:
            return _prev_df.iloc[-1]
        
      #  print(f"{self.blacklist} - doesnt have any bl on date")
        return None


    def createTSDF(self):

        arr = []
        cols = []

        for _ts in self.TS:
            ts = _ts.get()
            cols.append(_ts.getType())

            if isinstance(ts, pd.Series):
                ts = ts.to_frame()

            arr.append(ts)

        if len(arr) > 0:
            self.df = functools.reduce(lambda df1,df2: pd.merge(df1,df2,on='Date'), arr)
            self.df.columns = cols
            
            #print(self.df)
            return self.df

    def getFirstDate(self):
        
        first = True
        
        for _ts in self.TS:
            #print(_ts.get())
            if first:
                _start = _ts.getFirstDataPoint()
                first = False
                continue

            #print(_ts.getFirstDataPoint(), _start)
            if _ts.getFirstDataPoint() < _start:
                _start = _ts.getFirstDataPoint()
            
            return _start

    def getLastDate(self):

        first = True
        
        for _ts in self.TS:

            #print(_ts.get())
            if first:
                _last = _ts.getLastDataPoint()
                first = False
                continue
            
            #print(_ts.getLastDataPoint(), _last)
            if _ts.getLastDataPoint() > _last:
                _last = _ts.getLastDataPoint()
            
            return _last

    #This method does not increase range of abuseipdb time series
    def patchProphetTS(self):
        
        sX = None
        fX = None

        if len(self.TS) == 0:
            print("returning == 0")
            return 0

        for _ts in self.TS:
            if _ts.getType() == 'abuseipdb':
                sX = _ts.getFirstDataPoint()
                fX = _ts.getLastDataPoint()
                break
        
        if sX is None or fX is None:
            print("CANT GET ABUSEIPDB")
            return

        for _ts in self.TS:
            
            if _ts.getType() == 'abuseipdb':
                continue

            _first = None
            _last = None

            if _ts.getFirstDataPoint() > sX:

                delta =  _ts.getFirstDataPoint() - sX
                _days = pd.date_range(sX, periods=delta.days, freq='D').rename("Date")
                _first = pd.Series(0, index=_days)
                

            if _ts.getLastDataPoint() < fX:

                delta =  fX - _ts.getLastDataPoint()
                _days = pd.date_range(_ts.getLastDataPoint() + datetime.timedelta(days=1), periods=delta.days, freq='D').rename("Date")
                _last = pd.Series(0, index=_days)

            if _first is not None or _last is not None:
                objs = [_first, _ts.get().iloc[:,0], _last]
                con = pd.concat(objs)
                _ts.ts = con

        return 1

    def patchTS(self):
        #pd.options.display.max_rows = 999

        if len(self.TS) == 0:
            print("returning == 0")
            return 0

        elif len(self.TS) == 1:
            return 1

        sX = self.getFirstDate()
        fX = self.getLastDate()

        for _ts in self.TS:
            

            _first = None
            _last = None

            if _ts.getFirstDataPoint() > sX:

                delta =  _ts.getFirstDataPoint() - sX
                _days = pd.date_range(sX, periods=delta.days, freq='D').rename("Date")
                _first = pd.Series(0, index=_days)
                

            if _ts.getLastDataPoint() < fX:

                delta =  fX - _ts.getLastDataPoint()
                _days = pd.date_range(_ts.getLastDataPoint() + datetime.timedelta(days=1), periods=delta.days, freq='D').rename("Date")
                _last = pd.Series(0, index=_days)

            if _first is not None or _last is not None:
                objs = [_first, _ts.get().iloc[:,0], _last]
                con = pd.concat(objs)
                _ts.ts = con

        return 1

    def __str__(self):
        return self.ip
    
    def addEntity(self, entity, feed, blacklist=False):

        if blacklist:
            self.blacklist = entity
            return

        _ts = TS(entity, feed)
        
        if feed != "greynoise": 
            self.TS.append(_ts)
        else:
            self.grey = entity

    def getTS(self):
        return self.TS
            
    def addModel(self, model):
        self.models.append(model)

    def emmDistance(self):

        if self.good or self.bad: #Dont find distance with itself
            return

        print(f"{self.ip} === DISTANCE ===")
        if len(self.models) == 0:
            print("Host does not have any models")
            return

        goodModel = self.evalEngine.goodDF

        for m in self.models:

            if m is None:
                return

            for k, v in m.items(): 

                
                dist = Helper.distance(v['values'], goodModel.mean())
                print(f"Distance {dist} - Threshold {self.evalEngine.goodBadDistance()}")
                if dist > self.evalEngine.goodBadDistance():
                    print("Distance greater than threshold - marking as malicious")
                    
                    self.em_result = True

                else:
                    print("Distance lower than threshold - marking as benign")
                    
                    self.em_result = False
            

    # Find distance between known good model, and this hosts model
    def emDistance(self, goodModels):

        if self.good or self.bad: #Dont find distance with itself
            return

        #print(self.models)
        print(self.ip + " FINDING DISTANCE")
        if len(self.models) == 0:
            print("Host does not have any models")
            return

        for m in self.models:
            goodModel = None
            
            if m is None:
                continue

            for k, v in m.items():
                modelType = v['modelType']
                feedType = v['feedType']

                for gm in goodModels:
                    for k, j in gm.items():
                        if j['modelType'] == modelType and j['feedType'] == feedType:
                            goodModel = j

                if not goodModel:
                    print("Good model not found for type - " + modelType)
                    
                else:
                    print(goodModel)
                    print(v)
                    plt.plot(goodModel['bin_edges'][1:], goodModel['cdf']/goodModel['cdf'][-1])
                    plt.plot (v['bin_edges'][1:], v['cdf']/v['cdf'][-1])

                    print("=== DISTANCE ===")
                    print(Helper.distance(v['values'], goodModel['values']))
                    plt.show()

    def ksDistance(self, goodModels):

        if self.good: #Dont find distance with itself
            return

        print(self.ip + " FINDING DISTANCE")
        if len(self.models) == 0:
            print("Host does not have any models")
            return

        for m in self.models:
            goodModel = None
            
            if m is None:
                return

            for k, v in m.items():
                modelType = v['modelType']
                feedType = v['feedType']

                for gm in goodModels:
                    for k, j in gm.items():
                        if j['modelType'] == modelType and j['feedType'] == feedType:
                            goodModel = j

                if not goodModel:
                    print("Good model not found for type - " + modelType)
                    
                else:
                    #print(goodModel)
                    #print(v)
                    plt.plot(goodModel['bin_edges'][1:], goodModel['cdf']/goodModel['cdf'][-1])
                    plt.plot (v['bin_edges'][1:], v['cdf']/v['cdf'][-1])

                    print("=== DISTANCE ===")
                    value, pvalue = Helper.ks_distance(v['values'], goodModel['values'])
                    print(value, pvalue)
                    if pvalue < 0.01:
                        print("Less than 0.01, reject null hyposthesis - distributions are different")
                        self.ks_result = True
                    else:
                        print("Greater than 0.01, accept null hyposthesis - distributions are the same")
                        self.ks_result = False
                    plt.show()


class TS():

    def __init__(self, ts, feed):
        self.ts = ts
        self.feed = feed
    
    def getFirstDataPoint(self):
        return self.ts.first_valid_index()

    def getLastDataPoint(self):
        return self.ts.last_valid_index()

    def get(self):
        return self.ts
    
    def getType(self):
        return self.feed

class Hosts():

    def __init__(self, evalEngine):
        self.hosts = {}
        self.evalEngine = evalEngine


    def getHost(self, ip):
        return self.hosts[ip] if ip in self.hosts else None

    def addHost(self, ip):

        if self.getHost(ip):
            return self.getHost(ip)

        host = Host(ip, self.evalEngine)
        self.hosts[ip] = host
        return host
        
    def getHosts(self):
        return self.hosts
    
    def findDistance(self):

        goodModel = None

        #for _, host in self.getHosts().items():

         #   if host.good:
         #           ip = host.ip
         #           goodModel = host.models
         #           break

        #if goodModel is None:
         #   print("ERROR: Model of good IP not found")
        #    return
        
        for _, host in self.getHosts().items():
            host.emmDistance()






        

