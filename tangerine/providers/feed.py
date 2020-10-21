class Feed():

    def __init__(self):
        pass
    
    def g_query(self, ioc: ["ioc_type", "ioc"]):
        pass

    def parse(self, response):
        pass

    def get_ts(self, data):
        pass

    def get_blacklists(self, data):
        pass

    def hook_factory(self, *factory_args, **factory_kwargs):
        def response_hook(response, *request_args, **request_kwargs):

            response.ioc = factory_kwargs['ioc']
            response.type = self.__str__()
            return response 
        return response_hook