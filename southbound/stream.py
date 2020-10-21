from pyspark.streaming import StreamingContext
from pyspark.streaming.kafka import KafkaUtils

class StreamListener:

    def __init__(self, sc, spark_session, config):
        self.sc = sc
        self.spark_session = spark_session
        self.config = config
        self.ssc = StreamingContext(sc, self.config['modules']['clementine']['interval'])

    def createStream(self, subject="windows"):

        # kafkaParams = {"metadata.broker.list": self.config['kafka']['uri'] + ":" + self.config['kafka']['port'],}

       # return KafkaUtils.createDirectStream(self.ssc, topics=[subject], kafkaParams=kafkaParams)
        return KafkaUtils.createStream(self.ssc, self.config['kafka']['uri'] + ":" + self.config['kafka']['port'], "citrus-streaming-consumer", {subject: 4})
    
    def start(self):
        self.ssc.start()
        self.ssc.awaitTermination()
    
    def stop(self):
        self.ssc.stop()

    
    