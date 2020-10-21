from pyspark.ml import Pipeline
from pyspark.ml.feature import StringIndexer, OneHotEncoder, VectorAssembler
from pyspark.sql.functions import col
from pyspark.ml.feature import StringIndexer
from pyspark.ml.feature import VectorIndexer
from pyspark.ml.feature import IndexToString
from pyspark.ml import Pipeline
from pyspark.ml.evaluation import MulticlassClassificationEvaluator
from pyspark.mllib.evaluation import MulticlassMetrics
from pyspark.ml.classification import LogisticRegression, GBTClassifier, RandomForestClassifier
from sklearn.metrics import confusion_matrix
import pandas as pd

class ML:

    def __init__(self):
        pass
    
    def predict(self, model, df):

        df = self.dropNonTCPUDP(df)
        
        catCols = []
        numCols = ['avg_ipt', 'bytes_in', 'bytes_out', 'entropy', 'total_entropy', 'num_pkts_out', 'num_pkts_in', 'duration']
        labelCol = 'label'

        data = self.get_dummy(df, catCols, numCols, labelCol)
        data.cache()
        preds = model.transform(data)
        return preds

    def train(self, df):
        pass

    def ExtractFeatureImp(self, featureImp, dataset, featuresCol):
        list_extract = []
        for i in dataset.schema[featuresCol].metadata["ml_attr"]["attrs"]:
            list_extract = list_extract + dataset.schema[featuresCol].metadata["ml_attr"]["attrs"][i]
        varlist = pd.DataFrame(list_extract)
        varlist['score'] = varlist['idx'].apply(lambda x: featureImp[x])
        return(varlist.sort_values('score', ascending = False))

    def dropNonTCPUDP(self, df):

        df = df.filter( (df.proto == '17') | (df.proto == '6') )
        return df

    def train_test(self, df):
        
        df = self.dropNonTCPUDP(df)

        catCols = []
        numCols = ['avg_ipt', 'bytes_in', 'bytes_out', 'entropy', 'total_entropy', 'num_pkts_out', 'num_pkts_in', 'duration']
        labelCol = 'label'

        data = self.get_dummy(df, catCols, numCols, labelCol)
        data.show()

        labelIndexer = StringIndexer(inputCol='label',
                             outputCol='indexedLabel').fit(data)

        labelIndexer.transform(data)

        featureIndexer = VectorIndexer(inputCol="features", \
                                        outputCol="indexedFeatures").fit(data)
        featureIndexer.transform(data)

        (trainingData, testData) = data.randomSplit([0.7, 0.3])
        trainingData.cache()
     #   trainingData.repartition(200)
        testData.cache()
       # testData.repartition(200)
        trainingData.show(5,False)
        testData.show(5,False)

        rf = RandomForestClassifier(featuresCol='indexedFeatures', labelCol='indexedLabel')
        gbt = GBTClassifier(featuresCol='indexedFeatures', labelCol='indexedLabel')
        logr = LogisticRegression(featuresCol='indexedFeatures', labelCol='indexedLabel')

        # Convert indexed labels back to original labels.
        labelConverter = IndexToString(inputCol="prediction", outputCol="predictedLabel",
                               labels=labelIndexer.labels)
        
        pipeline = Pipeline(stages=[labelIndexer, featureIndexer, gbt, labelConverter])
        model = pipeline.fit(trainingData)
        predictions = model.transform(testData)
        # Select example rows to display.
        predictions.select("features","label","predictedLabel", "prediction")

        # Select (prediction, true label) and compute test error
 
        print(self.getTestError(predictions))
        self.printMetrics(predictions)
      #  print(self.ExtractFeatureImp(model.stages[-2].featureImportances, testData, "features"))

        return model


    def getTestError(self, preds, indexedLabel="indexedLabel", predictionCol="prediction", metricName="accuracy"):
        evaluator = MulticlassClassificationEvaluator(
            labelCol=indexedLabel, predictionCol=predictionCol, metricName=metricName
        )
        accuracy = evaluator.evaluate(preds)
        return accuracy, (1 - accuracy)

    def printMetrics(self, preds, prediction="indexedLabel", indexedLabel="prediction"):
        metrics = MulticlassMetrics(preds.select(prediction, indexedLabel).rdd)

        labels = [0, 1]
        for label in sorted(labels):
            try:
                print("Class %s precision = %s" % (label, metrics.precision(label)))
                print("Class %s recall = %s" % (label, metrics.recall(label)))
                print("Class %s F1 Measure = %s" % (label, metrics.fMeasure(label, beta=1.0)))
            except:
                print("No malicious predictions")

    def skCM(self, preds, label='label', predLabel='predictedLabel'):
        y_true = preds.select(label)
        y_true = y_true.toPandas()

        y_pred = preds.select(predLabel)
        y_pred = y_pred.toPandas()

        cnf_matrix = confusion_matrix(y_true, y_pred,labels=['benign', 'malicious'])
        return cnf_matrix

    def getConfusionMatrix(self, preds, prediction="prediction", indexedLabel="indexedLabel"):
        metrics = MulticlassMetrics(preds.select(prediction, indexedLabel).rdd)

        return (metrics.confusionMatrix())


    def get_dummy(self, df,categoricalCols,continuousCols,labelCol):

        indexers = [ StringIndexer(inputCol=c, outputCol="{0}_indexed".format(c))
                    for c in categoricalCols ]

        # default setting: dropLast=True
        encoders = [ OneHotEncoder(inputCol=indexer.getOutputCol(),
                    outputCol="{0}_encoded".format(indexer.getOutputCol()))
                    for indexer in indexers ]

        assembler = VectorAssembler(inputCols=[encoder.getOutputCol() for encoder in encoders]
                                    + continuousCols, outputCol="features")

        pipeline = Pipeline(stages=indexers + encoders + [assembler])

        model=pipeline.fit(df)
        data = model.transform(df)

        data = data.withColumn('label',col(labelCol))

        return data.select('features','label')
    
    