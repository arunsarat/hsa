#!/usr/bin/python

import urllib2, json

FLOWS_QUERY = 'http://127.0.0.1:8080/stats/flow/{}'
SWITCHES_QUERY = 'http://127.0.0.1:8080/stats/switches'

    def save_object_to_file(self, file):
        '''
        Depreciated
        saves all the non-custom transfer function rules to a file
        '''
        print "=== Saving transfer function to file %s ==="%file
        f = open(file, 'w')
        f.write("%d$%s$%d$%d$%d$\n"%(2*self.length,\
                                     self.prefix_id,\
                                     self.next_id,\
                                     self.lazy_eval_active,\
                                     self.send_on_receiving_port)
                )
        for b in self.lazy_eval_bytes:
            f.write("%d$"%b)
        f.write("#\n")
        for rule in self.rules:
            f.write("%s$"%rule["action"])
            f.write("%s$"%rule["in_ports"])
            f.write("%s$"%wildcard_to_str(rule["match"]))
            f.write("%s$"%wildcard_to_str(rule["mask"]))
            f.write("%s$"%wildcard_to_str(rule["rewrite"]))
            f.write("%s$"%wildcard_to_str(rule["inverse_match"]))
            f.write("%s$"%wildcard_to_str(rule["inverse_rewrite"]))
            f.write("%s$"%rule["out_ports"])
            f.write("#")
            for ra in rule["affected_by"]:
                f.write("%d;%s;%s#"%(self.rules.index(ra[0]),\
                                     wildcard_to_str(ra[1]),\
                                     ra[2]))
            f.write("$")
            f.write("#")
            for io in rule["influence_on"]:
                f.write("%d#"%self.rules.index(io))
            f.write("$%s$"%rule["file"])
            for ln in rule["line"]:
                f.write("%d,"%ln)
            f.write("$%s$\n"%rule["id"])
        f.close()
        print "=== Transfer function saved to file %s ==="%file

def parse_json(url_str):
	url = urllib2.urlopen(url_str)
	obj = json.load(url)
	print "#### Fetching JSON for URL = {} ####".format(url_str)
	#print "Printing JSON= {}".format(obj)
	return obj


def get_flows():
	switches = parse_json(SWITCHES_QUERY)
	for sw in switches:
		print "switch={}".format(sw)
		url = FLOWS_QUERY.format(sw)
		obj = parse_json(url)
		for flow in obj.get(str(sw)):
			print "actions={}".format(flow.get("actions"))
			print "match={}".format(flow.get("match"))

if __name__ == '__main__' :
	get_flows()
