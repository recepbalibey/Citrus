from statistics import mean

class DataCleaner():

    def __init__(self):

        self.cleaners = []
        self.setup_cleaners()
    
    def setup_cleaners(self):
        self._dionaea = DionaeaCleaner()
        self._cowrie = CowrieCleaner()
        self._joy = JoyCleaner()
        self.cleaners.append(self._dionaea)
        self.cleaners.append(self._cowrie)
        self.cleaners.append(self._joy)

    def clean(self, data, data_type):

        cleaned = data.map(getattr(self, '_' + data_type).clean)
        return cleaned

class JoyCleaner(DataCleaner):
    def __init__(self):
        pass

    def clean(self, row):
        clean = {}

        try:
            data = row[1]

        except:
            data = row

        #if data['da'] == '10.100.100.198':
            #return None #Return none as logstash sending logs to ELK
        if 'packets' in data:
            ipt = []
            for packet in data['packets']:
                ipt.append(packet['ipt'])

            if len(ipt) > 0:
                clean['avg_ipt'] = str(mean(ipt))
            else:
                clean['avg_ipt'] = str(0)
            
            
        if 'pr' in data:
            clean['proto'] = data['pr']
        if '@timestamp' in data:
            clean['timestamp'] = data['@timestamp']
        if 'num_pkts_in' in data:
            clean['num_pkts_in'] = data['num_pkts_in']
        else:
            clean['num_pkts_in'] = 0

        if 'num_pkts_out' in data:
            clean['num_pkts_out'] = data['num_pkts_out']
        else:
            clean['num_pkts_out'] = 0

        if 'bytes_in' in data:
            clean['bytes_in'] = data['bytes_in']
        else:
            clean['bytes_in'] = 0

        if 'bytes_out' in data:
           clean['bytes_out'] = data['bytes_out']
        else:
            clean['bytes_out'] = 0

        if 'da' in data:
            clean['dest_ip'] = data['da']
        elif 'dest_ip' in data:
            clean['dest_ip'] = data['dest_ip']

        if 'sa' in data:
            clean['src_ip'] = data['sa']
        elif 'src_ip' in data:
            clean['src_ip'] = data['src_ip']

        if 'sp' in data:
            clean['src_port'] = data['sp']
        elif 'src_port' in data:
            clean['src_port'] = data['src_port']

        if 'dp' in data:
            clean['dest_port'] = data['dp']
        elif 'dest_port' in data:
            clean['dest_port'] = data['dest_port']

        #clean['src_port'] = data['sp']
        #clean['dest_port'] = data['dp']

        if 'time_start' in data:
            clean['time_start'] = str(data['time_start'])
        if 'time_end' in data:
            clean['time_end'] = str(data['time_end'])

        if 'total_entropy' in data:
            clean['total_entropy'] = str(data['total_entropy'])
        else:
            clean['total_entropy'] = 0

        if 'entropy' in data:
            clean['entropy'] = str(data['entropy'])
        else:
            clean['entropy'] = 0

       # if 'expire_type' in data:
       #     clean['expire_type'] = data['expire_type']
       # else:
       #     clean['expire_type'] = ''

        if 'geoip' in data:

            if 'asn' in data['geoip']:
                clean['asn'] = data['geoip']['asn']
            if 'country_name' in data['geoip']:
                clean['country'] = data['geoip']['country_name']

        #if 'probable_os' in data:
            #if 'out' in data['probable_os']:
                #clean['joy_os'] = data['probable_os']['out']

        return clean

class CowrieCleaner(DataCleaner):
    def __init__(self):
        pass

    def clean(self, row):

        data = row[1]
        for desc, item in data.copy().items():
            if isinstance(item, dict):
                for i, it in item.items():
                    if not isinstance(it,dict):
                        data[i] = it
                del data[desc]
            if item is None:
                del data[desc]
            #if desc == 'src_ip':
            #    del data[desc]

        return data

class DionaeaCleaner(DataCleaner):

    def __init__(self):
        pass

    def clean(self, row):
        
        data = row[1]
        for desc, item in data.copy().items():
            if isinstance(item, dict):
                for i, it in item.items():
                    if not isinstance(it,dict):
                        data[i] = it
                del data[desc]
            if item is None:
                del data[desc]
        #if 'username' in data:
        #    data['username_attempted'] = 1
        #    del data['username']
        #else: 
        #    data['username_attempted'] = 0
        if 'ip_rep' not in data:
            data['ip_rep'] = 0
        else:
            data['ip_rep'] = 1

        return data   

        