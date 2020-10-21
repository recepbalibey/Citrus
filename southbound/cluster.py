from pyspark import SparkConf
from pyspark import SparkContext
from pyspark.sql import SQLContext
from pyspark.sql import SparkSession
from pyspark.sql.functions import udf, lit, col, map_from_arrays, array
from pyspark.sql.types import MapType, StringType, StructType, StructField, ArrayType, DataType, IntegerType, LongType, FloatType
from pyspark.sql.functions import explode,  window, collect_list, to_timestamp
from pyspark.sql import functions as F
import sys
import os
import functools
sys.path.insert(0, '/../citrus_lib')
from citrus_lib.config import Config
from citrus_lib.spark_funcs import SparkFunctions
from citrus_lib.cleaner import DataCleaner
import datetime
import json


class ClusterOperations:

    def __init__(self, sc, spark_session, sqlContext):
        self.sc = sc
        self.spark_session = spark_session
        self.config = Config.get()
        self.streamingAttackerIPs = self.sc.broadcast(self.config['modules']['clementine']['attacker_ips'])
        self.spark_functions = SparkFunctions(self.streamingAttackerIPs)
        self.cleaner = DataCleaner()
        self.sqlContext = sqlContext

    def anonymise(self, df):
        anon = udf(self.spark_functions.anon, StringType())
        df = df.withColumn("src_ip", anon('src_ip'))
        df = df.withColumn("dest_ip", anon('dest_ip'))
        return df

    def castDF(self, df):

        df = df.withColumn("avg_ipt", df.avg_ipt.cast("float"))
        df = df.withColumn("bytes_in", df.bytes_in.cast("long"))
        df = df.withColumn("bytes_out", df.bytes_out.cast("long"))
        df = df.withColumn("entropy", df.entropy.cast("float"))
        df = df.withColumn("num_pkts_in", df.num_pkts_in.cast("long"))
        df = df.withColumn("num_pkts_out", df.num_pkts_out.cast("long"))
        df = df.withColumn("time_end", df.time_end.cast("long"))
        df = df.withColumn("time_start", df.time_start.cast("long"))
        df = df.withColumn("total_entropy", df.total_entropy.cast("float"))
        df = df.withColumn("duration", df.duration.cast("float"))
        df = df.filter(df.label != "outlier")
        return df

    def addTimestamp(self, df):
        to_secs = udf(lambda x: x / 10 ** (len(str(x)) - 10), FloatType())
        df = df.withColumn("timestamp", to_secs(df['time_start']))
        df = df.withColumn("timestamp", to_timestamp(df['timestamp']))
        df = df.orderBy(df['timestamp'])
        return df

    def unionAll(self, dfs):
        return functools.reduce(lambda df1, df2: df1.union(df2.select(df1.columns)), dfs)

    def addFeatures(self, df):

        # Add duration 
        # TODO: Add connection based features
        print(df.printSchema())
        print("start of features func")
        timeFix = udf(self.spark_functions.fixTime, StringType())
        df = df.withColumn("time_start", timeFix('time_start'))
        df = df.withColumn("time_end", timeFix('time_end'))
        print(df.show())
        print(df.printSchema())
        df = df.withColumn("time_start", df.time_start.cast("long"))
        df = df.withColumn("time_end", df.time_end.cast("long"))
        dur = udf(self.spark_functions.setDuration, StringType())
        df = df.withColumn("duration", dur('time_start', 'time_end'))
        df = df.withColumn("duration", df.duration.cast("float"))
        df = df.withColumn("entropy", df.entropy.cast("float"))
        df = df.withColumn("total_entropy", df.total_entropy.cast("float"))


        #Clean up rows
        df = df.filter(df.duration >= 0)
        df = df.filter(df.entropy >= 0)
        df = df.filter(df.total_entropy >= 0)

        df = df.withColumn("duration", df.duration.cast("string"))
        df = df.withColumn("entropy", df.entropy.cast("string"))
        df = df.withColumn("total_entropy", df.total_entropy.cast("string"))

        df = df.na.fill(0)
        
        return df

    def cleanStream(self, rdd, source="joy"):

        try:
            cleaned = self.cleaner.clean(rdd, source)
            df = self.spark_session.createDataFrame(cleaned)

        except:
            print("RDD is empty")
            return None
        
        labelRow = udf(self.spark_functions.labelStream, StringType())
        timeFix = udf(self.spark_functions.fixTime, StringType())
        dur = udf(self.spark_functions.setDuration, StringType())

        df = df.withColumn("time_start", timeFix('time_start'))
        df = df.withColumn("time_end", timeFix('time_end'))

        df = df.withColumn("label", labelRow('src_ip', 'dest_ip'))

        print(df.select('src_ip', 'dest_ip', 'label').show())

        df = df.withColumn("avg_ipt", df.avg_ipt.cast("float"))
        df = df.withColumn("bytes_in", df.bytes_in.cast("long"))
        df = df.withColumn("bytes_out", df.bytes_out.cast("long"))
        df = df.withColumn("entropy", df.entropy.cast("float"))
        df = df.withColumn("num_pkts_in", df.num_pkts_in.cast("long"))
        df = df.withColumn("num_pkts_out", df.num_pkts_out.cast("long"))
        df = df.withColumn("total_entropy", df.total_entropy.cast("float"))
        
        df = df.withColumn("time_end", df.time_end.cast("long"))
        df = df.withColumn("time_start", df.time_start.cast("long"))
        df = df.withColumn("duration", dur('time_start', 'time_end'))

        df = df.withColumn("duration", df.duration.cast("float"))
        df = df.na.fill(0)

        
        return df

    def processStream(self, time, rdd):
        pass

    def clean(self, rdd, source):

        cleaned = self.cleaner.clean(rdd, source)
        print(cleaned.take(5))

        schema = StructType([
                StructField('asn', StringType()),
                StructField('avg_ipt', StringType()),
                StructField('bytes_in', StringType()),
                StructField('bytes_out', StringType()),
                StructField('country', StringType()),
                StructField('dest_ip', StringType()),
                StructField('dest_port', StringType()),
                StructField('entropy', StringType()),
                StructField('num_pkts_out', StringType()),
                StructField('num_pkts_in', StringType()),
                StructField('proto', StringType()),
                StructField('src_ip', StringType()),
                StructField('src_port', StringType()),
                StructField('time_end', StringType()),
                StructField('time_start', StringType()),
                StructField('timestamp', StringType()),
                StructField('total_entropy', StringType())
        ])

        df = self.sqlContext.createDataFrame(cleaned, schema)

        print(df.show())
        print(df.printSchema())

        return df

    def getStreamAccumulators(self):
        return self.sc.accumulator(0), self.sc.accumulator(0), self.sc.accumulator(0), self.sc.accumulator(0)

    def applyLabels(self, df, labels, date):
        
        map_keys = array([lit(k) for k in labels.keys()])
        map_values = array([lit(v) for v in labels.values()])
        map_func = map_from_arrays(map_keys, map_values) 

        verdict = udf(self.spark_functions.finalVerdict, StringType())

        labelled_df = df.withColumn('src_verdict', map_func.getItem(df.src_ip)).withColumn('dest_verdict', map_func.getItem(df.dest_ip))
        
        labelled_df = labelled_df.withColumn('label', verdict('src_verdict', 'dest_verdict', 'src_ip', 'dest_ip'))

        to_drop = ['src_verdict', 'dest_verdict', 'asn', 'country', 'timestamp']

        labelled_df = labelled_df.drop(*to_drop)

        #Drop ips that are not labelled
        labelled_df.show()

        return labelled_df


    #TODO : Get dates ip active within honeypot
    #TODO : Right now only returns 1st date active
    def getDates(self, ip, ip_pd):

        return ip_pd[ip_pd['src_ip'] == ip]
        #return self.ip_pd['collect_list(timestamp)']

    def aggregate_ip(self, df):
        #df_ips = df.groupBy('src_ip').count().orderBy("count", ascending=False).select('src_ip')
        df_ips = df.groupBy('src_ip').agg(collect_list('timestamp')).alias('timestamp')
        return df_ips

    def rev_dns(self, df):
        udf_rev_dns = udf(self.spark_functions.ip_to_hostname, StringType())
        rev_dns_df = df.select('src_ip', udf_rev_dns('src_ip').alias('hostname'))
        return rev_dns_df

    def bin_agg_df(self, df, wind="5"):

        binned = df.groupBy(df['src_ip'], window(df["timestamp"], wind + " minutes")) \
            .sum('num_pkts_in', 'num_pkts_out', 'bytes_in', 'bytes_out') \
            .orderBy("window")
        return binned

    def bin_keep_df(self, df, wind="5",):

        binned = df.groupBy(df['src_ip'], window(df["timestamp"], wind + " minutes")) \
            .agg(collect_list('dest_port')) \
            .orderBy("window")
            #  .sum('num_pkts_in', 'num_pkts_out', 'bytes_in', 'bytes_out') \
        return binned
