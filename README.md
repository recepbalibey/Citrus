# Overview
Citrus: an intrusion detection framework which is adept at tackling emerging threats through the collection and   
labelling   of   live   attack   data,   as   well   as real-time classification of malicious behaviour via the utilisation of 
machine learning  algorithms.

Citrus is composed of several inter-connected components, and the architecture is presented below:
http://citrusframework.org/citrus/reference/html/index.html
https://www.kaggle.com/mryanm/luflow-network-intrusion-detection-data-set?select=README.md
https://www.kaggle.com/docxian/network-intrusion-detection-demo

<p align="center">
  <img src="https://github.com/ruzzzzz/Citrus/blob/main/imgs/SBI.png?raw=true" alt="Citrus Overview" width="500">
</p>

As illustrated, the Citrus architecture is composed of distinct components which interface with services deployed within the network, as well as remote services located on the Internet. The southernmost components within the figure represent these services which provide Citrus crucial input data necessary for its operation. Furthermore, they are also utilised for output operations, such as saving labelled telemetry to disk for future dissemination within the research community. 

The northernmost components represent the two modules implemented to aid CTI gathering and real time anomaly detection. Clementine is a component within Citrus which rapidly identifies malicious behaviour occurring within the local network through the utilisation of machine learning models. The Tangerine component within Citrus, performs automatic intrusion detection data set labelling through correlation with cyber threat intelligence service providers.

# CTI Services
Additionally, Citrus supports a variety of cyber threat intelligence services to correlate and label suspect telemetry including:

* Greynoise
* Maltiverse
* Shodan
* OTX
* Zoomeye
* HybridAnalysis
* Apility
* AbuseIPDB

The relationships derived from these services are mapped into a graphical representation using [NetworkX](https://networkx.github.io) library.
Based upon these relationships and the formation of graph-based feature clusters, captured telemetry is labelled to contribute to an intrusion detection data set, [LUFlow '20](https://github.com/ruzzzzz/LUFlow). An example of the nodes and their corresponding labels is presented below:

<p align="center">
  <img src="https://github.com/ruzzzzz/Citrus/blob/main/imgs/supernodes_legend.png?raw=true" alt="Labelled clusters" width="500">
</p>
