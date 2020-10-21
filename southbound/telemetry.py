from pyspark import SparkConf
from pyspark import SparkContext
from pyspark.sql import SQLContext
from pyspark.sql import SparkSession
from pyspark.sql.functions import udf, lit, col, map_from_arrays, array
from pyspark.sql.types import MapType, StringType, StructType, StructField, ArrayType, DataType, IntegerType, LongType
from pyspark.sql.functions import explode,  window, collect_list
from pyspark.sql import functions as F
import json


class TelemetryCollector:

    def __init__(self, sc, elas_uri, elas_port):
        self.sc = sc
        self.elas_uri = elas_uri
        self.elas_port = elas_port

    def save(self, df, index):

        df.write.format("org.elasticsearch.spark.sql").option(
            "es.resource", index
        ).option(
            "es.nodes", self.elas_uri
        ).option(
            "es.port", self.elas_port
        ).option(
            "es.write.operation", "index"
        ).mode("overwrite").save()

    def query(self, prefix, index, hpot_type, queryAll=False):

        if queryAll:
            q = """{
                    "query": {
                        "match_all":{}
                    }
            }""" 
        else:
            q = """{
                    "query": {
                        "match":{
                            "type":"%s"
                        }
                    }
            }""" % (hpot_type)

        es_read_conf = {
            "es.nodes": self.elas_uri,
            "es.port": self.elas_port,
            "es.resource": prefix + "-" + index,
            "es.query": q
        }


        es_rdd = self.sc.newAPIHadoopRDD(
                inputFormatClass="org.elasticsearch.hadoop.mr.EsInputFormat", 
                keyClass="org.apache.hadoop.io.NullWritable", 
                valueClass="org.elasticsearch.hadoop.mr.LinkedMapWritable", 
                conf=es_read_conf
        )


        print(es_rdd.first())
        return es_rdd

    def query_month(self, year, month, hpot, prefix):
        rdds = []
        for i in range(1, 32):
            if i < 10:
                monthStr = year + '.' + month + '.0' + str(i)
            else:
                monthStr = year + '.' + month + '.' + str(i)

            rdd = self.query(prefix, monthStr, hpot)
            rdds.append(rdd)
        
        return self.sc.union(rdds)