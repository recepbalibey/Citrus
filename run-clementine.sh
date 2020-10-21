#!/bin/bash
git pull
zip -r files.zip . -x 'citrus.py' '*.git*' '*downloads*' '*__pycache__*' '*pickles*'
spark-submit  --executor-memory 18G --jars=/dir/elasticsearch-spark-20_2.11-7.4.0.jar,/dir/spark-streaming-kafka-0-8-assembly_2.11-2.4.4.jar --py-files "files.zip" citrus.py -c
