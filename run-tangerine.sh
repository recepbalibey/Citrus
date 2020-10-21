#!/bin/bash
git pull
zip -r files.zip . -x 'citrus.py' '*.git*' '*downloads*' '*__pycache__*' '*pickles*'
spark-submit --total-executor-cores 20  --executor-memory 4G --jars=/path/to/citrus/lib/elasticsearch-spark-20_2.11-7.4.0.jar,/path/to/citrus/lib/spark-streaming-kafka-0-8-assembly_2.11-2.4.4.jar --py-files "files.zip" citrus.py -t
