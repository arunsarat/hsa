'''
Created on Sep 8, 2012

@author: peymankazemian
'''
from utils.helper import dotted_subnet_to_int, mac_to_int, dotted_ip_to_int, l2_proto_to_int
from utils.wildcard_utils import set_header_field
from utils.wildcard import wildcard, wildcard_create_bit_repeat, wildcard_to_str
from headerspace.tf import TF
import json, urllib2

class WildcardTypeEncoder(json.JSONEncoder):
  def default(self, obj):
    if isinstance(obj, wildcard):
      return wildcard_to_str(obj)
    return json.JSONEncoder.default(self, obj)

class OFProtoParser(object):
  
  def __init__(self):
    self.flows = {}
    self.multipath = {}
    self.ports = {}
    #self.ports["onix:controller(of_port_name)"] = True
    self.port_members = {}
    self.topology = {}
    self.port_map = {}
    self.switches = {}
    self.next_port_id = {}
    self.switch_counter = 0
    self.SWITCH_ID_MULTIPLIER = 100000
    self.PORT_TYPE_MULTIPLIER = 10000

    self.FLOWS_QUERY = 'http://127.0.0.1:8080/stats/flow/{}'
    self.SWITCHES_QUERY = 'http://127.0.0.1:8080/stats/switches'
    self.PORTS_QUERY = 'http://127.0.0.1:8080/stats/port/{}'
    self.TOPOLOGY_QUERY = 'http://127.0.0.1:8080/v1.0/topology/links'

    '''
    self.format = {"dl_src_pos":0, "dl_dst_pos":6, "dl_type_pos":12,
                   "nw_src_pos":14, "nw_dst_pos":18, "nw_tos_pos":22,
                   "dl_src_len":6, "dl_dst_len":6, "dl_type_len":2,
                   "nw_src_len":4, "nw_dst_len":4, "nw_tos_len":1,
                   "length":23
                   }
    '''
    '''
    self.format = {"nw_src_pos":0, "nw_dst_pos":4, "dl_type_pos":8, "nw_tos_pos":10,
                   "nw_src_len":4, "nw_dst_len":4, "dl_type_len":2, "nw_tos_len":1,
                   "length":11
                   }
    '''
    self.format = {"nw_dst_pos": 0,
                   "nw_dst_len": 4,
                   "length": 4
                   }

  def __parse_json(self, url_str):
    url = urllib2.urlopen(url_str)
    obj = json.load(url)
    print "#### Fetching JSON for URL = {} ####".format(url_str)
    # print "Printing JSON= {}".format(obj)
    return obj

  def get_topology(self, path):
    seen_link_groups = False
    switches = self.__parse_json(self.SWITCHES_QUERY)
    for sw in switches:
      sw_name = "s" + str(sw)
      self.switches[sw_name] = sw
      self.port_map[sw_name] = {}
      print "switch={}/{}".format(sw_name, self.switches[sw_name])

      port_url = self.PORTS_QUERY.format(sw)
      obj = self.__parse_json(port_url)
      for port in obj[str(sw)]:
        if port["port_no"] == "LOCAL":
          continue
        port_name = sw_name + ":" + str(port["port_no"])
        self.ports[port_name] = True
        self.port_map[sw_name][port_name] = self.SWITCH_ID_MULTIPLIER * int(sw) + port["port_no"]
        print "Ports={}/{}, UID={}".format(port_name, self.ports[port_name],
                                           self.port_map[sw_name][port_name])

    topo = self.__parse_json(self.TOPOLOGY_QUERY)
    print "### get_topology #### Parsed topology={}".format(topo)
    if len(topo) != 0:
      for link in topo:
        src_sw = link.get("src").get("name").split('-')[0]
        src_port = src_sw + ":" + link.get("src").get("port_no").strip('0')
        print "Source port={}".format(src_port)
        dst_sw = link.get("dst").get("name").split('-')[0]
        dst_port = dst_sw + ":" + link.get("dst").get("port_no").strip('0')
        self.topology[src_port] = dst_port
        print "### Adding Link### SRC={}, DST={}".format(src_port, self.topology[src_port])

    # filename = path + "/" + "topology.txt"
    # print "get_topology## Reading Topology ={}".format(filename)
    # f = open(filename, 'r')
    # for next_line in f:
    #   line = next_line.strip()
    #   if line.startswith("link_groups"):
    #     seen_link_groups = True
    #   if (seen_link_groups):
    #     if line.startswith("src_port"):
    #       src_port_seen = True
    #     elif line.startswith("dst_port"):
    #       dst_port_seen = True
    #     elif line.startswith("name") and src_port_seen:
    #       src_port_seen = False
    #       src_port = line.split("\"")[1]
    #     elif line.startswith("name") and dst_port_seen:
    #       dst_port_seen = False
    #       dst_port = line.split("\"")[1]
    #       self.topology[src_port] = dst_port
    #       print "read_topology_ascii## Adding Link### SRC={}, DST={}".format(src_port, self.topology[src_port])


  def get_flows(self):
    for sw_name in self.switches:
      sw = sw_name[-1:]
      print "get_flows ## sw={}".format(sw)
      flow_url = self.FLOWS_QUERY.format(sw)
      obj = self.__parse_json(flow_url)
      self.flows[sw_name] = []
      for flow in obj.get(str(sw)):
        in_ports = []
        #print "get_flows### match={}/len={}, actions={}".format(flow.get("match"), len(flow.get("match")), flow.get("actions"))
        match = flow.get("match")
        if match.get("in_port") is not None:
          priority = flow.get("priority")
          in_port = sw_name + ":" + str(match.get("in_port"))
          in_ports.append(in_port)
          flow_actions = flow.get("actions")[0]
          actions = self.__parse_flow_action(sw_name, flow_actions)
          if len(match) > 0:
            match = self.__parse_match(match)
          self.flows[sw_name].append({"match":match,
                                      "action":actions,
                                      "input_ports":in_ports,
                                      "priority":priority,
                                      "id":priority})
      print "## get_flows ## RTR={} ## flow={}".format(sw_name, self.flows[sw_name])

  def __parse_flow_action(self, sw, action):
    actions = {}
    if action.split(':')[1] != "CONTROLLER":
      actions["output"] = sw + ':' + action.split(':')[1]
    return actions


  def __parse_action(self,action):
    print "__parse_action## action={}".format(action)
    actions_str = action.split(",")
    actions = {}
    for action_str in actions_str:
      action_str = action_str.strip()
      if action_str.startswith("OUTPUT to port"):
        actions["output"] = action_str[len("OUTPUT to port "):]
        print "__parse_action## output={}".format(actions["output"])
      elif action_str.startswith("SET DL SRC to"):
        #actions["set_dl_src"] = action_str[len("SET DL SRC to "):]
        pass
      elif action_str.startswith("SET DL DST to"):
        #actions["set_dl_dst"] = action_str[len("SET DL DST to "):]
        pass
      elif action_str.startswith("SET NW SRC to"):
        actions["set_nw_src"] = action_str[len("SET NW SRC to "):]
      elif action_str.startswith("SET NW DST to"):
        actions["set_nw_dst"] = action_str[len("SET NW DST to "):]
      elif action_str.startswith("Pop IP"):
        actions["pop_ip"] = ""
      elif action_str.startswith("Push IP"):
        actions["push_ip"] = ""
    return actions

  def __parse_match(self, flow_match):
    match = wildcard_create_bit_repeat(self.format["length"],3)
    num_fields = 0
    #print "Flow Match={}".format(flow_match)
    if flow_match.get("nw_dst") != "":
          num_fields += 1
          print "flow DST{}".format(flow_match.get("nw_dst"))
          (ip,subnet) = dotted_subnet_to_int(flow_match.get("nw_dst"))
          print "ip={}, subnet={}".format(hex(ip),subnet)
          set_header_field(self.format, match, "nw_dst", int(ip), 32-subnet)
          match = wildcard_to_str(match)
          ret = ""
          for s in match.split(','):
            ret += s
          #print "##__parse_flow_match##ip={}, match={}/{}".format(hex(ip), match, ret)
    return ret

  def __parse_flow_match(self,flow_match):
    parts = flow_match.split(" ")
    match = wildcard_create_bit_repeat(self.format["length"],3)
    num_fields = 0
    for part in parts:
      if not part.startswith("priority") and part != "":
        fv = part.split("=")
        field = fv[0]
        value = fv[1]
        if field == "nw_dst":
          num_fields += 1
          (ip,subnet) = dotted_subnet_to_int(value)
          print "ip={}, subnet={}".format(hex(ip),subnet)
          set_header_field(self.format, match, field, int(ip), 32-subnet)
          print "##__parse_flow_match##ip={}, match={}".format(hex(ip), match)
        #elif field == "dl_type":
          #num_fields += 1
          #set_header_field(self.format, match, field, l2_proto_to_int(value), 0)
    if num_fields > 0:
      return match
    else:
      return None
        
  def __process_topo_entry(self,name,members,enabled):
    if len(members) > 0:
      self.port_members[name] = members
    else:
      if name in self.ports:
        self.ports[name] = (self.ports[name] or enabled)
      else:
        self.ports[name] = enabled
        print "##__process_topo_entry ## Adding Port={}/{}".format(name, self.ports[name])
  
  def __encode_port_list(self, ports, rtr):
    result = []
    for port in ports:
      parts = port.split(":")
      print "__encode_port_list ## Encoding port={} with ={}".format(port, self.get_port_id(parts[0], parts[1]))
      if len(parts) > 1 and self.ports[port] == True:
        result.append(self.get_port_id(parts[0], parts[1]))
      else:
        result.append(self.get_port_id(rtr, port))
    return result
  
  def __compress_port_list(self, lst):
    print "port linst initial: ",lst
    final_list = []
    sws = set()
    for port in lst:
      parts = (port.split(":"))
      sw = parts[0]
      p = parts[1]
      if port in self.topology:
        dst_port = self.topology[port]
      else:
        dst_port = port
      print "Dst Port={}/{} for Port={}/{}".format(dst_port, self.ports[dst_port], port, self.ports[port])
      if sw not in sws:
        sws.add(sw)

      if self.ports[port] and self.ports[dst_port]:
        final_list.append(port)
    print "port list final: ",final_list
    return final_list
    
  def __expand_mport(self,rtr,mport):
    mport_rules = self.multipath[rtr][mport]
    result = []
    for mport_rule in mport_rules:
      if "encap" in mport_rule or "decap" in mport_rule:
        pass
      elif "output" in mport_rule:
        result.append(mport_rule["output"])
    return result
      
  
  def __add_action_to_rule(self,action,rule,rtr):
    #print "Action:", action, " Rule: ",rule
    mask = wildcard_create_bit_repeat(self.format["length"],2)
    rewrite = wildcard_create_bit_repeat(self.format["length"],1)
    out_ports = []
    rw = False
    push = False
    pop = False
    for operation in action.keys():
      if operation == "output":
        '''
        if action[operation] in self.port_members:
          out_ports = self.__encode_port_list(self.port_members[action[operation]],rtr)
        else:
        '''
        if action[operation].startswith("mport"):
          out_ports = self.__expand_mport(rtr, action[operation])
        else:
          out_ports = []

          ports = action[operation].strip('[]').split('/')
          for p in ports:
            out_ports.append(p)
            print "__add_action_to_rule##Adding Port={} to Output Ports={}".format(p, out_ports)
        out_ports = self.__compress_port_list(out_ports)
        out_ports = self.__encode_port_list(out_ports, rtr)
        print "__add_action_to_rule##Output Ports={}".format(out_ports)
      elif operation == "push_ip":
        push = True
        rule["encap_pos"] = self.format["nw_src_pos"]
        rule["encap_len"] = 8
      elif operation == "pop_ip":
        pop = True
        rule["decap_pos"] = self.format["nw_src_pos"]
        rule["decap_len"] = 8
    rule["out_ports"] = out_ports

    if push:
      rule["action"] = "encap"
      rule["mask"] = mask
      rule["rewrite"] = rewrite
    elif pop:
      rule["action"] = "decap"
      rule["mask"] = None
      rule["rewrite"] = None
    elif rw:
      rule["action"] = "rw"
      rule["mask"] = mask
      rule["rewrite"] = rewrite
    else:
      rule["action"] = "fwd"
      rule["mask"] = None
      rule["rewrite"] = None
  
  def __generate_mp_tf_rules(self, rtr):
    result_rules = []
    for mp in self.multipath[rtr]:
      group_rule = {"action":"multipath","rules":[]}
      rule = {}
      rule["in_ports"] = [self.get_port_id(rtr, mp)+self.PORT_TYPE_MULTIPLIER]
      rule["match"] = wildcard_create_bit_repeat(self.format["length"],3)
      is_fwd_action = True
      for single_action in self.multipath[rtr][mp]:
        rule_copy = rule.copy()
        self.__add_action_to_rule(single_action,rule_copy,rtr)
        if (rule_copy["action"] != "fwd"):
          is_fwd_action = False
        group_rule["rules"].append(rule_copy)
      if (is_fwd_action):
        all_out_ports = []
        for g_rule in group_rule["rules"]:
          all_out_ports.extend(g_rule["out_ports"])
        s = set(all_out_ports)
        rule["out_ports"] = self.__compress_port_list(list(s))
        rule["action"] = "fwd"
        rule["mask"] = None
        rule["rewrite"] = None
        group_rule["rules"] = [rule]
        result_rules.append(group_rule)
      else:
        result_rules.append(group_rule)
    return result_rules
  
  def __generate_tf_rules(self,rtr):
    result_rules = []
    for flow in self.flows[rtr]:
      if flow["match"] == None:
        continue
      rule = {}
      rule["match"] = flow["match"]
      print "match={}".format(rule["match"])
      rule["in_ports"] = []
      if len(flow["input_ports"]) > 0:
        ports = flow["input_ports"]
        for p in ports:
          rule["in_ports"].append(self.get_port_id(rtr, str(p)))
          print "__generate_tf_rules## input_ports={}".format(rule["in_ports"])
      rule["priority"] = flow["priority"]
      rule["id"] = flow["id"]
      rule["out_ports"]=[]
      rule["out_ports"].append(self.get_port_id(rtr, str(flow["action"].get("output"))))
      print "__generate_tf_rules## output_ports={}".format(rule["out_ports"])
      rule["action"] = "fwd"
      #self.__add_action_to_rule(flow["action"],rule,rtr)
      rule["mask"]= None
      rule["inverse_match"] = None
      rule["rewrite"] = ""
      rule["inverse_rewrite"] = None
      rule["affected_by"] = None
      rule["influence_on"] = []
      rule["affected_by"] = []
      rule["file"]=""
      rule["line"]=""
      result_rules.append(rule)
    sorted(result_rules,key=lambda elem: elem["priority"])
    return result_rules

  def __generate_rtr_tf(self, rtr, path, flows):
    output_file = "%s/%s.tf" % (path, rtr)
    #rules_file = "%s/%s.rules.json" % (path, rtr)
    print "## __generate_rtr_tf router = {} flows = {} ".format(rtr, flows)
    tf = TF (self.format["length"] * 2)
    tf.load_from_str(flows)
    tf.save_object_to_file(output_file)
    print "generated transfer function for router = {} is = {} ".format(rtr, tf)

  def __generate_topology_rules(self,topology):
    result_rules = []
    i = 1;

    for link in topology["topology"]:
      i += 1
      rule= {}
      rule["match"]= ""
      rule["in_ports"] = []
      print "Link SRC={}".format(link["src"])
      rule["in_ports"].append(link["src"])
      rule["priority"] = 0
      rule["id"] = "link_%s"%(i)

      rule["out_ports"]= []
      rule["out_ports"].append(link["dst"])

      rule["mask"]= ""
      rule["inverse_match"] = ""
      rule["rewrite"] = ""
      rule["action"] = "link"
      rule["inverse_rewrite"] = ""
      rule["affected_by"] = ""
      rule["influence_on"] = []
      rule["affected_by"] = []
      rule["file"]=""
      rule["line"]=""
      result_rules.append(rule)
    sorted(result_rules,key=lambda elem: elem["priority"])
    return result_rules

  def __generate_topology_tf(self, path, topology):
    output_file = "%s/topology.tf" % (path)
    #topology_file = "%s/topology.json" % (path)
    tf = TF (self.format["length"] * 2)
    tf.load_from_str(topology)
    #print "__generate_topology_tf###Writing to TOPOLOGY={}".format(output_file)
    tf.save_object_to_file(output_file)
    print "generated Topology transfer function is = {} ".format(tf)

  def __generate_topology(self):
    topo = {"topology":[]}
    # add trk ports to self.ports
    for src_port in self.topology:
      dst_port = self.topology[src_port]
      if self.ports[src_port] and self.ports[dst_port]:
        print "connection: ",src_port," --> ",dst_port
        parts = src_port.split(":")
        src_id = self.get_port_id(parts[0], src_port)
        parts = dst_port.split(":")
        dst_id = self.get_port_id(parts[0], dst_port)
        topo["topology"].append({"src":src_id,"dst":dst_id})
    print "topology={}".format(topo)
    return topo
        
  def read_flows_ascii(self,filename):
    f = open(filename,'r')
    last_name_seen = ""
    flow_match = ""
    flow_actions = ""
    priority = 0
    ports = ""
    for next_line in f:
      line = next_line.strip()
      if line.startswith("entity_description"):
        last_name_seen = ""
        
      if last_name_seen == "" and line.startswith("name"):
        last_name_seen = line.split("\"")[1]
        self.flows[last_name_seen] = []
      elif last_name_seen != "":
        if line.startswith("flow_match"):
          flow_match = (line.split("\"")[1]).strip("[]")
        elif line.startswith("priority"):
          priority = int((line.split(":")[1]).strip())
        elif line.startswith("input_ports"):
          ports = line.split("[")[1].strip(']')
          print "input_ports={}".format(ports)
        elif line.startswith("flow_actions"):
          flow_actions = line.split("\"")[1]
          actions = self.__parse_action(flow_actions)
          match = self.__parse_flow_match(flow_match)
          self.flows[last_name_seen].append({"match":match,
                                             "action":actions,
                                             "input_ports":ports,
                                             "priority":priority,
                                             "id":priority})
      for rtr in self.flows.keys():
        print "####Switch={}###".format(rtr)
        i=0
        for flow in self.flows[rtr]:
          i+=1
          print"Flow={}##{}".format(i, self.flows[rtr])

  
  def read_flows_binary(self,filename):
    pass
  
  def read_multipath_ascii(self,filename):
    f = open(filename,'r')
    last_name_seen = ""
    last_port_seen = ""
    for next_line in f:
      line = next_line.strip()
      if line.startswith("entity_description"):
        last_name_seen = ""
        
      if last_name_seen == "" and line.startswith("name"):
        last_name_seen = line.split("\"")[1]
        self.multipath[last_name_seen] = {}
      elif last_name_seen != "":
        if line.startswith("name"):
          last_port_seen = line.split("\"")[1]
          self.multipath[last_name_seen][last_port_seen] = []
        elif line.startswith("actions"):
          action_buckets = line.split("\"")[1]
          actions = self.__parse_action(action_buckets)
          self.multipath[last_name_seen][last_port_seen].append(actions)
        
  def read_multipath_binary(self,filename):
    pass
  
  def read_topology_ascii(self,filename):
    f = open(filename,'r')
    seen_node_groups = False
    last_port_seen = ""
    last_switch = ""
    member_ports = []
    enabled = False
    seen_link_groups = False
    src_port_seen = False
    dst_port_seen = False
    src_port = ""
    dst_port = ""
    for next_line in f:
      line = next_line.strip()

      if line.startswith("switches"):
        self.switches = {}
      elif line.startswith("sw_name"):
        last_switch = line.split("\"")[1]
      elif last_switch != "" and line.startswith("dpid"):
        self.switches[last_switch] = int(line.split(":")[1])

      if line.startswith("ports") or line.startswith("interfaces"):
        last_port_seen = ""
        member_ports = []
      elif line.startswith("node_groups"):
        seen_node_groups = True
      elif seen_node_groups and line.startswith("name"):
        seen_node_groups = False
      elif line.startswith("link_groups"):
        seen_link_groups = True

      if (seen_link_groups):
        if line.startswith("src_port"):
          src_port_seen = True
        elif line.startswith("dst_port"):
          dst_port_seen = True
        elif line.startswith("name") and src_port_seen:
          src_port_seen = False
          src_port = line.split("\"")[1]
        elif line.startswith("name") and dst_port_seen:
          dst_port_seen = False
          dst_port = line.split("\"")[1]
          self.topology[src_port] = dst_port
          print "read_topology_ascii## Adding Link### SRC={}, DST={}".format(src_port, self.topology[src_port])
      else:
        if not seen_node_groups and last_port_seen == "" and line.startswith("name"):
          last_port_seen = line.split("\"")[1]
        elif last_port_seen != "" and line.startswith("name"):
          member_ports.append(line.split("\"")[1])
        elif last_port_seen != "" and line.startswith("enabled"):
          en = (line.split(":")[1]).strip()
          enabled = (en == "true")
          self.__process_topo_entry(last_port_seen, member_ports, enabled)

  def read_topology_binary(self,filename):
    pass

  def generate_port_map(self):
    port_list = self.ports.keys()
    port_list.extend(self.port_members.keys())
    for port in port_list:
      parts = port.split(":")
      if parts[0] not in self.port_map:
        self.port_map[parts[0]] = {}
      if parts[1] not in self.port_map[parts[0]]:
        print "port={}, DPID={}".format(port, self.switches[parts[0]])
        self.port_map[parts[0]][parts[1]] = self.SWITCH_ID_MULTIPLIER * self.switches[parts[0]] + int (parts[1])
        print "Port= {} UniqueID: {}".format(port, self.port_map[parts[0]][parts[1]])

  def generate_port_map1(self):
    port_list = self.ports.keys()
    port_list.extend(self.port_members.keys())
    for port in port_list:
      parts = port.split(":")
      if parts[0] not in self.port_map:
        self.port_map[parts[0]] = {}
        self.switch_counter += 1
        #self.switch_ids[parts[0]] = self.switch_counter
        self.next_port_id[parts[0]] = self.SWITCH_ID_MULTIPLIER * self.switch_counter
      if parts[1] not in self.port_map[parts[0]]:
        self.next_port_id[parts[0]] += 1
        self.port_map[parts[0]][parts[1]] = self.next_port_id[parts[0]]
    '''
    for rtr in self.multipath.keys():
      for m_port in self.multipath[rtr].keys():
        self.next_port_id[rtr] += 1
        self.port_map[rtr][m_port] = self.next_port_id[rtr]
    ''' 
  def get_port_id(self, rtr, port):
    if rtr in self.port_map:
      if port in self.port_map[rtr]:
        return self.port_map[rtr][port]
    return 0
  
  def get_port_name_by_id(self,port):
    parts = port.split(":")
    return self.get_port_id(parts[0], parts[1])

  def generate_topology (self, output_path):
    topo = self.__generate_topology()
    links = self.__generate_topology_rules(topo)
    topology = {"rules": links, "length": self.format["length"], "prefix_id": "topo",
                "next_id": 0, "lazy_eval_active": 0, "send_on_receiving_port": 0, "lazy_eval_bytes": [],
                "ports": None, "id": 0}

    f = open("%s/topology.json" % (output_path), 'w')
    f.write(json.dumps(topology, indent=1, cls=WildcardTypeEncoder))
    f.close()
    self.__generate_topology_tf(output_path, json.dumps(topology))

    print "topology saved to file topology.json (", len(topo["topology"]), " links)."
    f = open("%s/port_map.json" % (output_path), 'w')
    f.write(json.dumps(self.port_map, indent=1))
    f.close()

    f = open("%s/stages" % (output_path), 'w')
    f.write("1")
    f.close()


  def generate_rules(self,output_path):
    total = len(self.flows)
    count = 0
    for rtr in self.flows:
      rtr_ports = []
      for port in self.port_map[rtr]:
        if not port.startswith("mport"):
          rtr_ports.append(self.port_map[rtr][port])
      #f = open("%s/%s.rules.json"%(output_path,rtr), 'w')
      flow_id = self.switches[rtr]*10
      rules = self.__generate_tf_rules(rtr)
      tf = {"rules":rules, "length":self.format["length"], "prefix_id":rtr,
            "next_id":0, "lazy_eval_active":0, "send_on_receiving_port":0, "lazy_eval_bytes":[],
            "ports":rtr_ports, "id":flow_id}
      #print "## generate_rules ## TF = {}".format(tf)
      #f.write(json.dumps(tf, indent=1, cls=WildcardTypeEncoder))
      #f.close()
      self.__generate_rtr_tf(rtr, output_path, json.dumps(tf))
      count += 1
      print "generated transfer function for router ",rtr,". (",count,"/",total,")"
    '''
    total = len(self.multipath)
    count = 0
    for rtr in self.multipath:
      rtr_ports = []
      for port in self.port_map[rtr]:
        if not port.startswith("mport"):
          rtr_ports.append(self.port_map[rtr][port])
      f = open("%s/%s.mp.rules.json"%(output_path,rtr), 'w')
      rules = self.__generate_mp_tf_rules(rtr)
      tf = {"rules":rules, "ports":rtr_ports, "length":self.format["length"], "id":self.switches[rtr]*10+1}
      f.write(json.dumps(tf, indent=1, cls=WildcardTypeEncoder))
      f.close()
      count += 1
      print "generated multipath transfer function for router ",rtr,". (",count,"/",total,")"
      '''
      
  def generate_graph_file(self, output_path):
    f = open("%s/graph.json"%(output_path), 'w')
    s = set()
    graph = {"links":[], "nodes":[]}
    links = []
    for src_port in self.topology:
      dst_port = self.topology[src_port]
      if (src_port in self.ports) and (dst_port in self.ports):
        if self.ports[src_port] and self.ports[dst_port]:
          parts = src_port.split(":")
          src_id = int(self.get_port_id(parts[0], parts[1]) / self.SWITCH_ID_MULTIPLIER)
          parts = dst_port.split(":") 
          dst_id = int(self.get_port_id(parts[0], parts[1]) / self.SWITCH_ID_MULTIPLIER)
          s.add(src_id)
          s.add(dst_id)
          links.append( {"source":src_id, "target":dst_id} )
    nodes = list(s)
    for link in links:
      graph["links"].append({"source":nodes.index(link["source"]),"target":nodes.index(link["target"])})
    for node in nodes:
      graph["nodes"].append({"name":str(node)})
    f.write(json.dumps(graph, indent=1))
          
    
