Citrus: an intrusion detection framework which is adept at tackling emerging threats through the collection and   
labelling   of   live   attack   data,   as   well   as real-time classification of malicious behaviour via the utilisation of 
machine learning  algorithms.

Citrus is composed of several inter-connected components, and the architecture is presented below:

<p align="center">
  <img src="https://github.com/ruzzzzz/Citrus/blob/main/imgs/SBI.png?raw=true" alt="Citrus Overview" width="500">
</p>

Citrus supports a variety of cyber threat intelligence services to correlate and label suspect telemetry including:

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
