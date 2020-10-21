import logging
import functools
import pandas as pd
import json
from .ml import ML
import signal
import sys
import seaborn as sb

class Clementine():

    def __init__(self, _southbound):
        self.log = logging.getLogger('clementine')
        self._southbound = _southbound
        self.ml = ML()
        pd.set_option('display.max_columns', 20)
        signal.signal(signal.SIGINT, self.close)

    def run(self):

        #Load model if trained previously
        if self._southbound._pickler.existsModel("windows-gbt-3day"):
            self.model = self._southbound._pickler.getModel("windows-gbt-3day")

        else:        
            df = self.loadDataset()
            self.model = self.ml.train_test(df)
            self._southbound._pickler.saveModel(self.model, "windows-gbt-3day")

        sdf = self._southbound._stream.createStream("windows").repartition(100)
        self.tn, self.fn, self.fp, self.tp = self._southbound._cluster.getStreamAccumulators()
        self.consume(sdf)
        
    def consume(self, sdf):
        dstream = sdf.map(lambda x: json.loads(x[1]))
        dstream.foreachRDD(self.processStream)
        self._southbound._stream.start()

    def processStream(self, time, rdd):    
        cleaned = self._southbound._cluster.cleanStream(rdd, "joy")
        if cleaned:
            
            preds = self.ml.predict(self.model, cleaned)
            preds.cache()
            preds.select("prediction", "predictedLabel").show()
            acc, test_err = self.ml.getTestError(preds)
            print(f"Accuracy: {acc} Test error: {test_err}")

            skmatrix = self.ml.skCM(preds)
            _tn, _fp, _fn, _tp = skmatrix.ravel()
            self.accumulateMetrics(_tn, _fp, _fn, _tp)
            print(f"TN: {_tn}, FN {_fn} \nFP: {_fp}, TP: {_tp}")
            print(skmatrix)

    def accumulateMetrics(self, tn, fp, fn, tp):
        self.tn += tn
        self.fn += fn
        self.fp += fp
        self.tp += tp

    def loadDataset(self):

        df = self.loadAll()
        df = self._southbound._cluster.castDF(df)
        df = self._southbound._cluster.addTimestamp(df)

        df.show()
        df.printSchema()
        return df


    def loadCSV(self, file):

        if file in self._southbound._pickler.getLabelledFiles():

            return self._southbound._pickler.readCSVToDF(file, "prod").repartition(200)

        print(f"{file}  not found in HDFS - returning None")
        return None
        

    def loadModel(self, name):
        pass

    def close(self, sig, frame):
        print("Exiting clementine...")
        print(f"TN: {self.tn.value} FN {self.fn.value} \n FP: {self.fp.value}, TP: {self.tp.value}")
        precision = (self.tp.value / (self.tp.value + self.fp.value))
        print(f"Precision: { precision }")
        recall = (self.tp.value / ( self.tp.value + self.fn.value))
        print(f"Recall: { recall }")
        print(f"Accuracy: { ((self.tp.value + self.tn.value) / (self.tp.value + self.tn.value + self.fp.value + self.fn.value)) }")
        print(f"F-score: { 2 * ((precision * recall) / (precision + recall)) }")
        self._southbound._stream.stop()

    def loadAll(self):

        files = self._southbound.getLabelledFiles()

        dfs = []
        for file in files:
            df = self.loadCSV(file)
            if df:
                dfs.append(df)
            
        return self._southbound._cluster.unionAll(dfs).repartition(200)
    