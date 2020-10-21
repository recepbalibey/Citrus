import networkx as nx
import json
import pandas as pd
from sklearn.preprocessing import MinMaxScaler
from sklearn.cluster import KMeans
import sys
sys.path.insert(0, '/../citrus_lib')
from citrus_lib.host import *
class Cluster:

    def __init__(self, hosts, _southbound, geoip):
        self.hosts = hosts
        self._southbound = _southbound
        self.geoip = geoip
        
    def colourClusters(self, graph, labelDict):
        cols = []
        label_index = 0
        for counter, data in graph.nodes(data=True):

            if data['type'] == 'ip':
                if labelDict[counter]['verdict'] == 'malicious':
                    cols.append('red')
                else:
                    cols.append('green')
            else:
                cols.append('cyan')

        return cols

    def labelClusters(self, cluster_df, kmeans, graph):

        labels = kmeans.labels_

        cols = []
        cluster_cols = kmeans.labels_.astype(float)
            
        _filterDict = {}

        #Grab test features label from last item in labels
        test_label = kmeans.labels_[-1]

        label_index = 0
        for counter, data in graph.nodes(data=True):
            if data['type'] == 'ip':
                
                if labels[label_index] == test_label:
                   # print(f"Label {label_index} - {data['value']} Counter: {counter}")
                   # print(f"DF : {cluster_df.iloc[label_index]}")
                    cols.append('green')
                    _filterDict[counter] = { "ip" : data['value'], "label_index": label_index, "type": "outlier"}
                    label_index = label_index + 1

                else:
                   # print(f"Label {label_index} - {data['value']} Counter: {counter}")
                   # print(f"DF : {cluster_df.iloc[label_index]}")
                    cols.append('red')
                    _filterDict[counter] = { "ip" : data['value'], "label_index": label_index, "type": "supernode"}

                    label_index = label_index + 1

            else:
                cols.append('cyan')

        return cols, _filterDict

    def kmeans(self, cluster_df):
        scaler = MinMaxScaler()
       # cluster_df = cluster_df.drop(['eigen_cent', 'nns'], axis=1)
        cluster_df[['node_degrees', 'eigen_cent']] = scaler.fit_transform(cluster_df[['node_degrees', 'eigen_cent']])

        kmeans = KMeans(n_clusters=2).fit(cluster_df)
        return kmeans

    def draw_all(self, date):

        _map = {}
        _counter = 0

        G = nx.Graph()

        _ip_dic = {}

        _malt_bl_dic = {}
        _bl_dic = {}
        _asn_dic = {}
        _file_dic = {}

        #First get all blacklists seen on day
        #And get all ASNs of nodes
        for ip, host in self.hosts.getHosts().items():
            if host.asn is not None:
                if not host.asn in _asn_dic:
                    _asn_dic[host.asn] = _counter
                    _counter += 1

            if host.blacklist is not None:

                blacklists = host.getBlacklistsByDate(date)
                
                if blacklists is not None:
                
                    blacklists = blacklists.iloc[-1]
                   # print(f"{blacklists} blacklists on date!!")
                    blacklists = blacklists.split(",")
                    for blacklist in blacklists:
                        if not blacklist in _bl_dic and blacklist != 'None':
                            _bl_dic[blacklist] = _counter
                            _counter += 1

            if len(host.files) > 0:
                for sha, file in host.files.items():
                    if not sha in _file_dic:
                        _file_dic[sha]  = _counter
                        _counter += 1
            
            if host.malti_blacklist is not None:
                active_bl = host.getMaltiverseBlacklistsByData(date)
               # print(f"IP: {ip} | {json.dumps(active_bl, indent=4)}")

                if active_bl is not None:
                    for name, blacklist in active_bl.items():
                        if not name in _malt_bl_dic:
                            _malt_bl_dic[name] = _counter
                            _counter += 1


        print(json.dumps(_bl_dic, indent=4))
        print(json.dumps(_malt_bl_dic, indent=4))

        #Add all blacklists as nodes
        for bl, counter in _bl_dic.items():
            G.add_node(counter, value=bl, type='bl', counter=counter)

        #Add all ASN Nodes
        for asn, counter in _asn_dic.items():
            G.add_node(counter, value=asn, type='asn', counter=counter)

        #Add all files nodes
        for sha, counter in _file_dic.items():
            G.add_node(counter, value=sha, type='file', counter=counter)

        #Add all Maltiverse blacklist nodes
        for name, counter in _malt_bl_dic.items():
            G.add_node(counter, value=name, type='bl', counter=counter)
        
        
        #Add all contacted ips from files (if not seen in hosts)
        
        for ip, host in self.hosts.getHosts().items():
            if len(host.files) > 0:
                for sha, file in host.files.items():
                 #   print(f"==== File : {sha} Contacted IPs =====")
                #    print(file.getContactedIPs())

                    x = 0
                    for _contacted_ip in file.getContactedIPs():

                        #Limit to 50 otherwise shit gets fucked
                        if x > 25:
                            break

                        if not _contacted_ip in self.hosts.getHosts():
                  #          print(f"{_contacted_ip} not in hosts")
                            G.add_node(_counter, value=_contacted_ip, type='contacted_ip', counter=_counter)
                 
                            _ip_dic[_contacted_ip] = _counter

                            G.add_edge(_counter, _file_dic[sha], weight=0.5)

                            asn = self.geoip.getASN(_contacted_ip)

                            if asn is None:
                                continue

                            if  asn in _asn_dic:
                                G.add_edge(_counter, _asn_dic[asn])
                            
                            else:

                                _counter += 1
                                G.add_node(_counter, value=asn, type='asn', counter=_counter)
                                G.add_edge(_counter, _counter-1)
                                _asn_dic[asn] = _counter

                            _counter += 1
                            x += 1

                            #_item = {_counter: sha}
                            #_items.update(_item)
                            #_counter += 1

                            #_map[_contacted_ip] = _items
                            

       

        #Add all honeypot nodes 
        for ip, host in self.hosts.getHosts().items():
            
            if len(host.services) > 0 or host.blacklist is not None or host.asn is not None or len(host.files) > 0 or host.malti_blacklist is not None:
            
                G.add_node(_counter, value=str(ip), type='ip', counter=_counter)
                _items = {_counter: str(ip)}
                _counter += 1

            else:

                continue

            for port, service in host.services.items():
                
                #print(f"Port {port}")

                G.add_node(_counter, value=int(port), type='service', counter=_counter)
                _item = {_counter: int(port)}
                _items.update(_item)
                _counter += 1

                #G.add_edge(str(ip), int(port))

                #for s in service:

                    #print(f"Service: {s.getService()} App: {s.getApp()} Time: {s.getDate()} Feed: {s.getFeed()}")

            #Still need to add blacklist info to dict
            
            
            if host.blacklist is not None:

                blacklists = host.getBlacklistsByDate(date)
                
                if blacklists is not None:
                
                    blacklists = blacklists.iloc[-1]

                    blacklists = blacklists.split(",")
                    for blacklist in blacklists:
                        if blacklist != "None":
                            
                            _item = {_counter: str(blacklist)}
                            _items.update(_item)
                            _counter += 1

            if host.asn is not None:
                _item = {_counter: host.asn}
                _items.update(_item)
                _counter += 1


            #Add files to item dict
            if len(host.files) > 0:
                for sha, file in host.files.items():
                    
                    _item = {_counter: sha}
                    _items.update(_item)
                    _counter += 1
            
            #Add maltiverse blacklist items
            if host.malti_blacklist is not None:
                active_bl = host.getMaltiverseBlacklistsByData(date)
                if active_bl is not None:
                    for name, blacklist in active_bl.items():
                        _item = {_counter: name}
                        _items.update(_item)
                        _counter += 1

            #print(_items)
            _map[ip] = _items
        
        #print(_map)
        #Add edges 
        for ip, mapping in _map.items():

            _ip_key = min(mapping)
            _arr = []
            for k, v in mapping.items():
                if k == _ip_key:
                    continue

                if v in _bl_dic:
                    G.add_edge(_ip_key, _bl_dic[v], weight=3)
                elif v in _asn_dic:
                    G.add_edge(_ip_key, _asn_dic[v])
                elif v in _file_dic:
                    G.add_edge(_ip_key, _file_dic[v], weight=8)
                elif v in _malt_bl_dic:
                    G.add_edge(_ip_key, _malt_bl_dic[v], weight=3)
                else:
                    G.add_edge(_ip_key, k )

        self._southbound._pickler.saveGraph(G, date)

        return G

    def isLinkedToSupernode(self, graph, labels, dict):

        _labelDict = {}
        
        for counter, data in graph.nodes(data=True):
            if data['type'] == 'ip':
                _isLinkedToSupernode = False
                
                #IP is supernode
                if dict[counter]['type'] == 'supernode':
                    
                    
                    _isLinkedToSupernode = True
    

                else:

                    connected_nodes = nx.node_connected_component(graph, counter)
                    for node in connected_nodes:
                        if node in dict and dict[node]['type'] == 'supernode':
                            _isLinkedToSupernode = True

                whitelist = ['148.88.249.83', '148.88.249.85']

                if data['value'] in whitelist:
                    _isLinkedToSupernode = False
                    

                _labelDict[counter] = {'verdict': 'malicious' if _isLinkedToSupernode else 'outlier', 'ip': data['value']}

        return _labelDict

    def isNeighbourToSupernode(self, graph, labels, dict):

 
        cols = []

        _labelDict = {}
        
        for counter, data in graph.nodes(data=True):
            if data['type'] == 'ip':
                _isLinkedToSupernode = False
                
                #IP is supernode
                if dict[counter]['type'] == 'supernode':
                    
                    
                    _isLinkedToSupernode = True
    

                else:
                    
                    for neighbour, data in graph[counter].items():

                        if neighbour in dict and dict[neighbour]['type'] == 'supernode':
                            _isLinkedToSupernode = True
                            break
                        
                        neighbours_neighbours = graph[neighbour]

                        for n, data in neighbours_neighbours.items():
                            if n in dict and dict[n]['type'] == 'supernode':
                                _isLinkedToSupernode = True
                                break
                    
                whitelist = ['148.88.249.83', '148.88.249.85']

                if data['value'] in whitelist:
                    _isLinkedToSupernode = False

                _labelDict[counter] = {'verdict': 'malicious' if _isLinkedToSupernode else 'outlier', 'ip': data['value']}

        return _labelDict


    def calculateGraphFeatures(self, graph):

        hosts = {}
        for counter, data in graph.nodes(data=True):
            if data['type'] == 'ip':
                hosts[counter] = data['value']

        nns = {}
        #for counter, data in graph.nodes(data=True):
         #   if data['type'] == 'ip':
        #        i = 0
#
         #       for neighbour, data in graph[counter].items():

         #           neighbours_neighbours = graph[neighbour]
        #            for n, data in neighbours_neighbours.items():
       #                 i = i + 1

       #         nns[counter] = i

        #nns_data = [v for val, v in nns.items()]

      #  centrality = nx.betweenness_centrality(graph, weight='weight', normalized=True)
      #  cent_data = [ value for k, value in centrality.items() if k in hosts ]

        #Graph not connected
        #eccentricity = nx.eccentricity(graph)
       # ecc_data = [ value for k, value in eccentricity.items() if k in hosts ]

        #deg_cent = nx.degree_centrality(graph)
        #deg_cent_data = [value for k, value in centrality.items() if k in hosts]

        edge_degree = graph.degree(weight='weight')
        ed_data = [val for (node, val) in edge_degree if node in hosts]

        eigen_centrality = nx.nx.eigenvector_centrality_numpy(graph, weight='weight')
        ec_data = [ value for k, value in eigen_centrality.items() if k in hosts ]

        pd_index = [ counter for counter, ip in hosts.items() ]

        pd_data = { 'node_degrees': ed_data, 'eigen_cent': ec_data}

        df = pd.DataFrame(pd_data, index=pd_index)
        return df


    def addTest(self, graph):
        #Add test node - should never be malicious - Dictates which cluster labels are malicious/benign
        foundTest = False
        for counter, data in graph.nodes(data=True):
            
            if data['value'] == 'test' and data['type'] == 'ip':
                foundTest = True

        if foundTest == False:
            graph.add_node(99999999, value='test', type='ip')

    #original node colours
    def labelColour(self, G):
        _colours = []
        _labels = {}
        for counter, data in G.nodes(data=True):
            
            _labels[data['counter']] = data['value']
            #Blacklist
            if data['type'] == 'bl':
                _colours.append('red')
                
                continue
            #IP
            elif data['type'] == 'asn':
                _colours.append('yellow')
                continue
                
            elif data['type'] == 'ip':
                _colours.append('green')
                continue
                
            #Service
            elif data['type'] == 'service':
                _colours.append('blue')
                continue

            elif data['type'] == 'file':
                _colours.append('pink')
                continue

            elif data['type'] == 'contacted_ip':
                _colours.append('purple')
                continue

        return _labels, _colours

    

    def draw_old(self):

        date = '2020.02.24'
        G = nx.Graph()
        for ip, host in self.hosts.getHosts().items():
            
            if len(host.services) > 0 or host.blacklist is not None:
                
                G.add_node(str(ip))
            
            else:

                continue

            for port, service in host.services.items():
                
              #  print(f"Port {port}")

                G.add_node(int(port))
                G.add_edge(str(ip), int(port))

                for s in service:
                    pass
              #      print(f"Service: {s.getService()} App: {s.getApp()} Time: {s.getDate()} Feed: {s.getFeed()}")

            if host.blacklist is not None:

                print(host.blacklist)

                blacklists = host.getBlacklistsByDate(date)
                
                if blacklists is not None:
                
                    blacklists = blacklists.iloc[-1]

                    blacklists = blacklists.split(",")
                    for blacklist in blacklists:
                
                        if blacklist == "None":
                            break

                        else:
                            G.add_node(str(blacklist))
                            G.add_edge(str(ip), str(blacklist))

        nx.draw_networkx(G, with_labels=True, label=ip)
        

    def draw_hosts(self):

        date = '2020.02.24'

        _map = {}
        _counter = 0

        
        for ip, host in self.hosts.getHosts().items():
            
            if len(host.services) > 0 or host.blacklist is not None:
                G = nx.Graph()
                

                G.add_node(_counter, value=str(ip))
                _items = {_counter: str(ip)}
                _counter += 1
                
            else:

                continue

            for port, service in host.services.items():
                
                print(f"Port {port}")

                G.add_node(_counter, value=str(port))
                _item = {_counter: str(port)}
                _items.update(_item)
                _counter += 1

                #G.add_edge(str(ip), int(port))

                for s in service:

                    print(f"Service: {s.getService()} App: {s.getApp()} Time: {s.getDate()} Feed: {s.getFeed()}")

            if host.blacklist is not None:

             #   print(host.blacklist)

                blacklists = host.getBlacklistsByDate(date)
                
                if blacklists is not None:
                
                    blacklists = blacklists.iloc[-1]

                    blacklists = blacklists.split(",")
                    for blacklist in blacklists:
                
                        if blacklist == "None":
                            break

                        else:
                            G.add_node(_counter, value=str(blacklist))
                            _item = {_counter: str(blacklist)}
                            _items.update(_item)
                            _counter += 1

                            #G.add_edge(str(ip), str(blacklist))


            _ip_key = min(_items)
            #print(f"Lowest key in dict: {_ip_key}")
            _arr = []
            for k, v in _items.items():
                if k == _ip_key:
                    continue
                #print(f"Adding edge from {_ip_key} -> {k}")
                _arr.append( (_ip_key, k) )
            
            G.add_edges_from(_arr)
            #Set node colours

            print(_items)

            nx.draw_networkx(G, labels=_items, with_labels=True)
            #nx.draw_networkx_labels(G, pos, _items,font_size=12)
            

    def getContactedIPs(self, graph):
        _no_contacted = 0
        contacted = {}
        types=nx.get_node_attributes(graph,'type')
        for counter, data in graph.nodes(data=True):
            if data['type'] == 'file':
                i = 0

                for neighbour, weight in graph[counter].items():

                    
                    
                    type = types[neighbour]
                    if type == 'contacted_ip' or type == 'ip':
                            
             #           print(type)
                        i = i + 1


                contacted[counter] = i
            elif data['type'] == 'contacted_ip':
                _no_contacted = _no_contacted + 1
        
        
       # print(json.dumps(contacted, indent=4))
        print(f"No. contacted IPs: {_no_contacted}")
        return contacted