import os
import json

class Config:

    @staticmethod
    def get():
        config_path = os.path.dirname(os.path.realpath(__file__)) + "/../config.json"
        with open(config_path) as data_file:    
                return json.load(data_file)
