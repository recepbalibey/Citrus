import os
import pickle
from pyspark import SparkConf
from pyspark import SparkContext
from pyspark.sql import SQLContext
from pyspark.sql import SparkSession
from hdfs import Config
import sys
sys.path.insert(0, '/../citrus_lib')
from citrus_lib.host import *
from citrus_lib.host import Host as host
from hashlib import sha256
import networkx as nx
from pyspark.ml.pipeline import PipelineModel

class Pickler:

    def __init__(self, sc, spark_session, uri, port):

        self.sc = sc
        self.spark_session = spark_session
        self.df = []
        self.models = []
        self.graphs = []
        self.base_path = uri + ":" + port 
        self.local_pickle_path = os.path.dirname(os.path.realpath(__file__)) + '/../pickles/'

        self.pickle_path = '/user/hadoop/pickles/'
        self.model_path = '/user/hadoop/pickles/models/'

        self.dataset_path = self.pickle_path + "dataset/"
        self.private_release_path = self.dataset_path + "private/"
        self.anon_release_path = self.dataset_path + "github/"
        self.prod_release_path = self.dataset_path + "prod/"

        self.df_path = self.pickle_path + 'df/'
        self.graph_path = self.local_pickle_path + 'graphs/'
        self.labelled_df_path = self.df_path + 'labelled/'
        self.hdfs_client = Config().get_client('dev')
        
        self.load_df()
        self.load_models()
        self.load_graphs()


    #TODO: Implement generic methods for read dataset / model ONLY
    def read(self):
        pass

    def save(self):
        pass
    
    def getLabelledFiles(self):
        return self.hdfs_client.list(self.prod_release_path)

    def readCSVToDF(self, date, folder):
        return self.spark_session.read.option("header", True).csv(self.base_path + self.dataset_path + folder + "/" + date)

    def getLabelledTelemetry(self):
        return self.hdfs_client.list(self.private_release_path)
        
    def existsModel(self, name):
        res = self.hdfs_client.list(self.model_path)
        file_extension = '.model'
        if name + file_extension in res:
            return True

    def getModel(self, name):
        return PipelineModel.load(self.base_path + self.model_path + name + ".model")

    def isDateLabelled(self, date):
        res = self.hdfs_client.list(self.prod_release_path)
        file_extension = ".csv"

        if date + file_extension in res:
            return True

        return False

    def load_graphs(self):
        for file in os.listdir(self.graph_path):
        
            if file.endswith(".pickle"):
                self.graphs.append(file[:-7])

    def existsGraph(self, date):
        if date in self.graphs:
            return True
        return False
    
    def getGraph(self, date):
        if date in self.graphs:
            with open(self.graph_path + date + ".pickle", 'rb') as pickle_file:
                content = pickle.load(pickle_file)

                return content

    def saveGraph(self, G, date):
        if date in self.graphs:
            return False
        
        nx.write_gpickle(G, self.graph_path + date + ".pickle")
        self.graphs.append(date)

    def existsDF(self, date, source):

        #2020.03.01_joy
        hash = self.getHash(date, source)
        if hash in self.df:
            return True

        return False

    def load_df(self):

        #Load Joy Data
        res = self.hdfs_client.list(self.df_path + 'joy')
       # print(f"Joy Items in directory: {res}")
        for file in res:

            if file.endswith(".parquet"):
                
                self.df.append(sha256(file[:-8].encode('utf-8')).hexdigest()) 
                
        #Load graph features DF
        res = self.hdfs_client.list(self.df_path + 'graph')
      #  print(f"Graph DF Items in directory: {res}")
        for file in res:

            if file.endswith(".parquet"):
                
                self.df.append(sha256(file[:-8].encode('utf-8')).hexdigest()) 

        res = self.hdfs_client.list(self.df_path + 'labelled')
     #   print(f"Labelled Items in directory: {res}")
        for file in res:

            if file.endswith(".parquet"):
                
                self.df.append(sha256(file[:-8].encode('utf-8')).hexdigest()) 

        # TODO : Load others?

    def saveModel(self, model, name):
        model.save(self.base_path + self.model_path + name + ".model")

    def load_models(self):
        res = self.hdfs_client.list(self.model_path)
        for file in res:
            if file.endswith(".model"):
                self.models.append(file.split('.')[0]) 

    def saveDFToCSV(self, df, date, folder, coalesced=False):

        if coalesced:
            df.coalesce(1).write.csv(self.base_path + self.pickle_path + "dataset/" + folder + '/' + date + '.csv', header=True)
        else:
            df.write.csv(self.base_path + self.pickle_path + "dataset/" + folder + '/' + date + '.csv', header=True)
            df.write.parquet(self.base_path + self.pickle_path + "dataset/" + folder + '/' + date + '.parquet')

    def saveDF(self, df, date, source):
        hash = self.getHash(date, source)
        if hash in self.df:
            return False

        else:
            df.write.parquet(self.base_path + self.df_path + source + '/' + date + "_" + source + '.parquet')
            self.df.append(hash)  

    def getDF(self, date, source):

        hash = self.getHash(date, source)

        if hash in self.df:

            df = self.spark_session.read.parquet(self.base_path + self.df_path + source + '/' + date + "_" + source + '.parquet')
            return df

        return False

    def getHash(self, date, source):

        id = date + "_" + source
        hash = sha256(id.encode('utf-8')).hexdigest()
        return hash


class Pickle:

    def __init__(self, id):
        self.id = id
        