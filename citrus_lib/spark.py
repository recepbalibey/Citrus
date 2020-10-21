from pyspark import SparkConf
from pyspark import SparkContext
from pyspark.sql import SQLContext
from pyspark.sql import SparkSession
from pyspark.sql.functions import udf, lit, col, map_from_arrays, array
from pyspark.sql.types import MapType, StringType, StructType, StructField, ArrayType, DataType, IntegerType, LongType
from pyspark.sql.functions import explode,  window, collect_list
from pyspark.sql import functions as F
import pandas as pd
import threading
import matplotlib.pyplot as plt
import collections

class Spark:

    def __init__(self, spark_uri, spark_port):

        self.conf = SparkConf()
        self.conf.setMaster('spark://' + spark_uri + ':' + spark_port)
        self.conf.setAppName('citrus-spark')

        self.sc = SparkContext.getOrCreate()
        self.spark_session = SparkSession(self.sc)
        self.sqlContext = SQLContext(self.sc)
        self.silence_spark(self.sc)

    def silence_spark(self, sc):

        logger = sc._jvm.org.apache.log4j
        logger.LogManager.getLogger("org").setLevel(logger.Level.ERROR)
        logger.LogManager.getLogger("akka").setLevel(logger.Level.ERROR)





    


        

