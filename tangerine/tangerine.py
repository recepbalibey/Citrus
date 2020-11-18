import sys
import logging
import uuid
sys.path.insert(0, '/../citrus_lib')
from citrus_lib.host import *
from datetime import timedelta, datetime
import os
import time
import json
import threading
import uuid
from mpl_toolkits.mplot3d import Axes3D
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import MinMaxScaler
from sklearn.cluster import KMeans
import pandas as pd
from .intel import Intelligence
from dateutil.parser import parse as dateparse
import hashlib
from citrus_lib.evalengine import EvalEngine
import matplotlib.pyplot as plt
import networkx as nx
import collections
from sklearn.cluster import AgglomerativeClustering
from citrus_lib.geoip import GeoIP
from .clustering import Cluster

class Tangerine():

    def __init__(self, hosts, _southbound, evalEngine):

        self.log = logging.getLogger('tangerine')
        self.intel = Intelligence(hosts, _southbound)

        self.hosts = hosts
        self._southbound = _southbound
        
        self.geoip = GeoIP(os.path.dirname(os.path.realpath(__file__)) + "/../lib/geoip.mmdb")

        self.evalEngine = evalEngine
        self.cluster = Cluster(self.hosts, self._southbound, self.geoip)

        self.config_path = os.path.dirname(os.path.realpath(__file__)) + "/../config.json"
        with open(self.config_path) as data_file:    
            self.config = json.load(data_file)
            
        self.mode = self.config['modules']['tangerine']['mode']


    def run(self):

        first = True
        prev_date = None

        while True:

            if first:
                date = self.config['modules']['tangerine']['date']
                dt_date = datetime.strptime(date, '%Y.%m.%d')
                prev_date = date
                first = False

            else:  

                dt_prev_date = datetime.strptime(prev_date, '%Y.%m.%d')
                dt_date = dt_prev_date + timedelta(days=1)
                date = dt_date.strftime("%Y.%m.%d")
                prev_date = date

            if dt_date.date() == datetime.today().date():
                print("On current date - Cannot label until day after")
                break

            if not self._southbound._pickler.isDateLabelled(date):
                print(f"{date} is not labelled.. Starting...")
                source = self.config['modules']['tangerine']['data_source']
                self.graph(date, source)
            else:
                print(f"{date} is already labelled.. Skipping..")
            
            time.sleep(2)

    def inCache(self, date, source):
        return True if self._southbound._pickler.existsDF(date, source) else False

    def loadTelemetry(self, date, source, type='logstash'):

        #if self.inCache(date, source):
            #print("DF In cache, loading...")
            #df = self._southbound._pickler.getDF(date, source)
            #print(df.show())
            #df_ips = self._southbound._cluster.aggregate_ip(df)
            #ip_pd = df_ips.toPandas()
            #return ip_pd, df

        #else:

        print("DF Not cached, requesting from ES...")
        rdd = self._southbound._telemetry.query(type, date, source)
        print(rdd.take(5))
        cleaned = self._southbound._cluster.clean(rdd, source)
        cleaned.repartition(200)
        print(cleaned)
        df_ips = self._southbound._cluster.aggregate_ip(cleaned).repartition(200)
        ip_pd = df_ips.toPandas()
        return ip_pd, cleaned

    def graph(self, date, source):

        pd.set_option('display.max_rows', 1000)
        ips, df = self.loadTelemetry(date, source)

        print(ips)

        self.add_hosts(ips['src_ip'].values.tolist())

        if self._southbound._pickler.existsGraph(date):
            print("Found graph for this date - Loading from HDFS")
            graph = self._southbound._pickler.getGraph(date)
            
        else:
            print("Found no graph on this date - performing lookups")
            intel = self.intel.lookup_iocs(ips)
            self.intel.parse_intel(intel, mode='graph')
            self.geoip.addDefaultASN(self.hosts.getHosts())
            graph = self.cluster.draw_all(date)

        plt.figure(figsize=(20,14))

        self.cluster.addTest(graph)

        graph_feature_df = self.cluster.calculateGraphFeatures(graph)
        print(graph_feature_df.tail(5))

        pos = nx.spring_layout(graph)
        
        kmeans = self.cluster.kmeans(graph_feature_df)
        labels = kmeans.labels_

        cols, _filterDict = self.cluster.labelClusters(graph_feature_df, kmeans, graph)

        #Draw graph feature clusters
      #  plt.scatter(graph_feature_df['node_degrees'],graph_feature_df['eigen_cent'] , c= kmeans.labels_.astype(float), s=50)
       # plt.show()

        #Draw graph of corresponding clusters
      #  nx.draw_networkx(graph, pos=pos, node_color=cols, dpi=1000, font_size=4)
       # plt.show()

        #Get nodes linked to supernodes identified by clustering
        labelDict = self.cluster.isLinkedToSupernode(graph, labels, _filterDict)
        cols = self.cluster.colourClusters(graph, labelDict)
        
        nx.draw_networkx(graph, pos=pos, node_color=cols, dpi=1000, font_size=4, with_labels=False)

        ipKeyLabels = {}
        for counter, data in labelDict.items():
            ipKeyLabels[data['ip']] = data['verdict']

        labelled_df = self._southbound._cluster.applyLabels(df, ipKeyLabels, date)    
        self.saveLabelledDF(labelled_df, date)
        plt.show()

    def saveLabelledDF(self, df, date):

        #First construct meta-features (duration etc) and save
        
        df = self._southbound._cluster.addFeatures(df)
        df.repartition(200)
        df.cache().count()
        self._southbound._pickler.saveDFToCSV(df, date, "prod", coalesced=False)
        self._southbound._pickler.saveDFToCSV(df, date, "private", coalesced=True)

        #Then anonymise external IPs for public release
        anon_df = self._southbound._cluster.anonymise(df)
        self._southbound._pickler.saveDFToCSV(anon_df, date, "github", coalesced=True)

    def add_hosts(self, ips):
   
        for ip in ips:
            if not self.hosts.getHost(ip):
                self.hosts.addHost(ip) 


        



        

