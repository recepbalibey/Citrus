import uuid
import threading
import logging
import json
import time
import paramiko
import os
import os.path
from paramiko.py3compat import input
import datetime
try: 
    import queue
except ImportError:
    import Queue as queue



class Consumer(threading.Thread):

    
    def __init__(self, hosts, intel, db, config, queue, host_queue):

        self.config = config
        self.queue = queue
        self.intel = intel
        self.config = config
        self.db = db
        self.hosts = hosts
        self.host_queue = host_queue
        self.pkey_file = os.path.dirname(os.path.realpath(__file__)) + "/id_rsa"
        self.downloads_folder = os.path.dirname(os.path.realpath(__file__)) + "/downloads"
        logging.getLogger("paramiko").setLevel(logging.WARNING)
        threading.Thread.__init__(self)

    def run(self):
        pass
    
    def parse(self):
        pass
    
    # Query db against filename
    def query_db_filename(self, filename, index):

        query = {"query": {"match": {"id": filename}}}
        res = self.db.search(index=index, body=query)
        #print("found " + str(res['hits']['total']))
        data = []
        for doc in res['hits']['hits']:
            data.append(doc)
        
        if data:
            return res 
        else:
            return False


class Cowrie(Consumer):

    def __init__(self, hosts, intel, db, config, queue, host_queue):
        
        super().__init__(hosts, intel, db, config, queue, host_queue)
        self.log = logging.getLogger('cowrie')
        self.downloads_folder = self.downloads_folder + "/cowrie"
        self.client =  paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
    def __repr__(self):
        return "cowrie"
    

 
    #TODO: Get archived downloads if not retrived previously
    #Periodically scrape for downloads vis SSH
    #Find more efficient alternative
    def run(self):
        while True:

            host = self.config['tpot']['host']
            port = self.config['tpot']['port']
            user = self.config['tpot']['user']
            try:
                self.client.connect(host, port=port, username=user, key_filename=self.pkey_file)

                remote_download_dir = "/data/cowrie/downloads"
                ftp = self.client.open_sftp()
                ftp.chdir(remote_download_dir)
                files = ftp.listdir()
                #print(files)
            except:
                print("Could not connect to remote server")
                time.sleep(5)
                continue

            for file in files:
                if not super().query_db_filename(file, 'downloads'):
                    
                    entry = {"filename": 'cowrie/' + file, "hash": file}
                    self.queue.put(entry)
                        
            ftp.close()
            time.sleep(5)
        
    def parse(self, _json):

        #TODO Parse metadata

        data = json.loads(_json['message'])
        #print(data)
        

        if 'src_ip' in data:
            src_ip = data["src_ip"]

        host = self.hosts.getHost(src_ip)
        if  host is None:
            host = self.hosts.addHost(uuid.uuid4(), src_ip, "cowrie")
            print('New host added | {}'.format(src_ip))     
            #self.intel.query('zoom', 'ip:'+ src_ip, self.host_queue)
            self.intel.query('shodan', src_ip, self.host_queue)
            #print(type(zoomeye))
            #zoomeye = zoomeye.decode('utf8')
            #zoomeye = json.loads(zoomeye)
            
            #print(type(zoomeye))
            #for item in zoomeye['matches']:
                #print(item)
            #print(zoomeye)

        host.addEvent(data, uuid.uuid4())
        self.parse_event(data, host)

    def parse_event(self, json, host):
        event_type = json['eventid']
        src_ip = json['src_ip']

        print("Cowrie event: " + event_type + " from ip: " + src_ip)

class Dionaea(Consumer):

    def __init__(self, hosts, intel, db, config, queue, host_queue):
        self.log = logging.getLogger('dionaea')
        super().__init__(hosts, intel, db, config, queue, host_queue)
        self.client =  paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.downloads_folder = self.downloads_folder + "/dionaea"

    def __repr__(self):
        return "dionaea"

    def run(self):
        t = 0
        while t == 1:

            host = self.config['tpot']['host']
            port = self.config['tpot']['port']
            user = self.config['tpot']['user']
            self.client.connect(host, port=port, username=user, key_filename=self.pkey_file)

            remote_download_dir = "/data/dionaea/binaries"
            ftp = self.client.open_sftp()
            ftp.chdir(remote_download_dir)
            files = ftp.listdir()
            print(files)
            for file in files:
                if not super().query_db_filename(file, 'downloads'):
                    print(file + " not found in DB")
                    try:
                        ftp.get(remote_download_dir + "/" + file, self.downloads_folder + "/" + file)
                    except:
                        print("Could not copy remote file")
                    
                    path = self.downloads_folder + "/" + file
                    if os.path.exists(path):
                        entry = {"filename": 'dionaea/' + file, "hash": file}
                        #self.db['dionaea_downloads'].insert_one(entry)
                        self.queue.put(entry)
                        
            ftp.close()
            time.sleep(5)

    def parse(self, json):
        #print(json)

        pass

class DownloadConsumer(threading.Thread):

    def __init__(self, tangerine):

        self.tangerine = tangerine
        self.queue = tangerine.download_queue
        self.log = logging.getLogger('tangerine')
        threading.Thread.__init__(self)

    def run(self):
        print("consuming")
        while True:

            ret = self.queue.get()
            if ret:
                print("Retrieved " + ret['filename'])
                self.tangerine.process_download(ret)
                self.queue.task_done()
            else:
                print("queue is empty")
            time.sleep(0.5)