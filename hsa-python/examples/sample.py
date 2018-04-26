#!/usr/bin/python

import urllib2, json

FLOWS_QUERY = 'http://127.0.0.1:8080/stats/flow/{}'
SWITCHES_QUERY = 'http://127.0.0.1:8080/stats/switches'

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
