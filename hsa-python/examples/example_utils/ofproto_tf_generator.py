'''
Created on Sep 9, 2012

@author: Peyman Kazemian
'''
import argparse
import os
import urllib2, json
from headerspace.tf import TF
from time import time
from config_parser.openflow_parser import OFProtoParser

'''
settings is a dictionary containing the following:
@key: @value
@required "zone_names": list of zone names 
@required "input_path": input path relative to current directory
@required "output_path": output path relative to current directory
@optional "hs_format": a hs_format dictionary
'''
settings = {"rtr_names": [],
            "zone_names": ["zone1"],
            "input_path": "input_files",
            "output_path":"tf_files",
            "topology": "tf"
            }



parser = argparse.ArgumentParser(description='Generate Transform Functions for mininet switches')
parser.add_argument('fabric',
                   help='Name of the fabric that needs to be analyzed')
parser.add_argument("-i", "--input_path", default="config",
                    help="path to the directory where input configuration files store.")
parser.add_argument("-o", "--output_path", default="tfs",
                    help="Path to the directory where transfer function files are stored.")
args = parser.parse_args()




def generate_transfer_functions(settings):
  st = time()
  parser = OFProtoParser()
  print "==== procesing ",args.fabric," ===="

  input_path = args.input_path + "/" + args.fabric
  output_path = args.output_path + "/" + args.fabric

  # if not os.path.exists(input_path):
  #     print "Configuration Directory ={} doesn't exist".format(input_path)
  #     return
  if not os.path.exists(output_path):
      os.makedirs(output_path)

  stages_file = output_path + "/" + "stages"
  f = open(stages_file, 'w')
  f.write("1")

  #parser.read_flows_ascii("%s/%s-flows.proto"%(input_path,args.fabric))
  #parser.read_topology_ascii("%s/%s-topology.proto"%(input_path,args.fabric))
  #parser.generate_port_map()
  #parser.generate_graph_file(settings["output_path"])
  parser.get_topology(input_path)
  parser.get_flows()

  parser.generate_topology(output_path)
  parser.generate_rules(output_path)
  en = time()

  print "total switch count: ", len(parser.port_map.keys())
  print "switched from port map: ",parser.port_map.keys()
  print "total switch count: ", len(parser.flows.keys())
  print "switched from flows: ",parser.flows.keys()
  flow_count = 0
  for rtr in parser.flows:
    print "Switch ",rtr," has ",len(parser.port_map[rtr])," ports and ",len(parser.flows[rtr]), " flows."
    flow_count += len(parser.flows[rtr])
  print "Total flow count: ",flow_count
  print "Total rule nodes: ",flow_count
  print "parsing time: ",(en-st)
  return parser

if __name__ == '__main__':
    generate_transfer_functions(settings)
