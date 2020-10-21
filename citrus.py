import gevent.monkey
gevent.monkey.patch_all()

from clementine.clementine import Clementine
from tangerine.tangerine import Tangerine
import logging
import os
import json
from citrus_lib.host import Hosts
import uuid
from citrus_lib.spark import Spark
from southbound.southbound import Southbound
from citrus_lib.evalengine import EvalEngine
from citrus_lib.config import Config
import argparse
log = logging.getLogger('citrus')

class Citrus:

    class __Citrus:
        
        def __init__(self, clementine, tangerine):

            self.log = logging.getLogger('citrus')
            self.config = Config.get()
            self.evalEngine = EvalEngine(self.config)
            self.hosts = Hosts(self.evalEngine)
            self.evalEngine.addHosts(self.hosts)
            
            self.spark = Spark(self.config['spark']['uri'], self.config['spark']['port'])
            self._southbound = Southbound(self.spark)
            self.loadModules(clementine, tangerine)

            self.run()

        def loadModules(self, clementine, tangerine):

            if clementine:

                self._clementine = Clementine(self._southbound)
                self._clementine.run()

            elif tangerine:
                self._tangerine = Tangerine(self.hosts, self._southbound, self.evalEngine)
                self._tangerine.run()

            else:
                print("No module selected... \n Exiting...")
                return

            
        def run(self):

            self.log.info("Starting citrus")

        def __str__(self):
            return repr(self)

    instance = None

    def __init__(self, clem, tang):
        if not Citrus.instance:
            
            Citrus.instance = Citrus.__Citrus(clem, tang)
            
        else:
            raise Exception

    def __getattr__(self, name):
        return getattr(self.instance, name)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-c", "--clementine",
                        action='store_true',
                        help="Enable Clementine module")
    group.add_argument("-t", "--tangerine",
                        action='store_true',
                        help="Enable Tangerine module")
    args = parser.parse_args()
    Citrus(args.clementine, args.tangerine)