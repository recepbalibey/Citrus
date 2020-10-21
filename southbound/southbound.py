from .pickler import Pickler
from .intelcollector import IntelCollector
from .telemetry import TelemetryCollector
from .stream import StreamListener
from .cluster import ClusterOperations
import os
import json

class Southbound:

    def __init__(self, spark):
        self.loadConfig()
        self.init_modules(spark.sc, spark.spark_session, spark.sqlContext)
        
    def init_modules(self, sc, spark_session, sqlContext):
        self._pickler = Pickler(sc, spark_session, self.config['hdfs']['uri'], self.config['hdfs']['port'])
        self._intel = IntelCollector()
        self._telemetry = TelemetryCollector(sc, self.config['elastic']['uri'], self.config['elastic']['port'])
        self._stream = StreamListener(sc, spark_session, self.config)
        self._cluster = ClusterOperations(sc, spark_session, sqlContext)

    def loadConfig(self):
        self.config_path = os.path.dirname(os.path.realpath(__file__)) + "/../config.json"
        with open(self.config_path) as data_file:    
            self.config = json.load(data_file)

    def handle(self, **kwargs):
        component = kwargs['component']
        return getattr(self, '_' + component).handle(kwargs)