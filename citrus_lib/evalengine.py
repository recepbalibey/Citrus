import os
import json
import pandas as pd
from .host import *
from .helper import Helper
class EvalEngine():

    def __init__(self, config):
        
        self.loadConfig(config)

    def loadConfig(self, config):

        self.goodIPs = config['goodIPs']
        self.badIPs = config['badIPs']


    # Patches known good and bad DF data to be same length
    # Used when calculating mean of good/bad IPs for comparison

    def patchDF(self):
        #print("PATCHING DFFFFF")
        goodHosts = []
        badHosts = []

        goodFurthestStartDate = None
        goodFurthestEndDate = None
        
        badFurthestStartDate = None
        badFurthestEndDate = None

       # print("BEFORE PATCHING GOOD/BAD DFs")
        for _, host in self.hosts.getHosts().items():

            if host.df is None:
                    continue

            if host.good:

             #   print(f"{host.ip} \n {host.df}")
                goodHosts.append(host)

                if goodFurthestStartDate == None:
                    goodFurthestStartDate = host.df.first_valid_index()
                
                if goodFurthestEndDate == None:
                    goodFurthestEndDate = host.df.last_valid_index()


                if host.df.first_valid_index() > goodFurthestStartDate:
                    goodFurthestStartDate = host.df.first_valid_index()
                
                if host.df.last_valid_index() < goodFurthestEndDate:
                    goodFurthestEndDate = host.df.last_valid_index()
                
            elif host.bad:
            #    print(f"{host.ip} \n {host.df}")
                badHosts.append(host)
                

                if badFurthestStartDate == None:
                    badFurthestStartDate = host.df.first_valid_index()

                if badFurthestEndDate == None:
                    badFurthestEndDate = host.df.last_valid_index()

                if host.df.first_valid_index() > badFurthestStartDate:
                    badFurthestStartDate = host.df.first_valid_index()
                
                if host.df.last_valid_index() < badFurthestEndDate:
                    badFurthestEndDate = host.df.last_valid_index()

        #print("AFTER PATCHING")    
        for g in goodHosts:

            if goodFurthestStartDate > g.df.first_valid_index() or g.df.last_valid_index() > goodFurthestEndDate:
                g.df = g.df[goodFurthestStartDate:goodFurthestEndDate]

        #        print(f"{g.ip} \n {g.df}")

        for b in badHosts:
            if badFurthestStartDate > b.df.first_valid_index() or b.df.last_valid_index() > badFurthestEndDate:
                b.df = b.df[badFurthestStartDate:badFurthestEndDate]

         #       print(f"{b.ip} \n {b.df}")

    #    print(f"Good IP start date - {goodFurthestStartDate} ")
    #    print(f"Bad IP start date - {badFurthestStartDate} ")
                


    def addEvalIPs(self, df):

        data = [] #Insert known GOOD & Bad value into (top of) IP DataFrame

        for ip in self.goodIPs:

            data.insert(0, {'src_ip': ip, 'collect_list(timestamp)': 'good'})

        for ip in self.badIPs:

            data.insert(0, {'src_ip': ip, 'collect_list(timestamp)': 'bad'})

        ips = pd.concat([pd.DataFrame(data), df], ignore_index=True)

        return ips

    def addHosts(self, hosts):
        self.hosts = hosts

    def modelGood(self):

        goodHosts = []
        for _, host in self.hosts.getHosts().items():

            if host.good:
                goodHosts.append(host)


        values = []
        for host in goodHosts:

            

            for model in host.models:
                if model is None:
                    continue
                for _, v in model.items():
                    values.append(v['values'])
        
        df = pd.DataFrame(values)
       # print(df)
       # print(df.mean())

        self.goodDF = df


    def modelBad(self):

        badHosts = []
        for _, host in self.hosts.getHosts().items():

            if host.bad:
                badHosts.append(host)


        values = []
        for host in badHosts:

            for model in host.models:
                if model is None:
                    continue
                for _, v in model.items():
                    values.append(v['values'])
        
        df = pd.DataFrame(values)
      #  print(df)
      #  print(df.mean())

        self.badDF = df

    def goodBadDistance(self):
        
        
        dist = Helper.distance(self.goodDF.mean(), self.badDF.mean())
   #     print("DISTANCE BETWEEN MODEL BAD v GOOD")
        return dist

