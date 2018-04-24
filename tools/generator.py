# generator.py
# generate exploit scripts

import json

LOGS_PATH = "logs/"
EXPLOIT_PATH = "exploits/"
EXPLOIT_CLASS = {
	"SQL Injection": "sqli",
	"Server Side Code Injection": "ssci",
	"Directory Traversal": "dt",
	"Open Redirect": "or",
	"CSRF": "csrf",
	"Command Injection": "ci",
}


class ExploitGenerator:
	"""
	Script Generator Module
	Generates exploit scripts based on the logs
	
	Sample JSON:
	{
	   "class":"SQL Injection",
	   "results":{
	   		"http://target.com":[
	        	{
            		"endpoint":"/search",
            		"params":{
               			"key1":"value1"
	            	},
	            	"method":"POST"
	        	},
				...
			]
		},
		...
	}
	"""

	def __init__(self):
		self.counter = 0

	def craft_get_url(self, url, params):
		params_str = []
		for key, value in params.items():
			params_str.append("{}={}".format(key, value))
		return "{}?{}".format(url, "&".join(params_str))

	def write_to_json(self, exploit_class, logs):
		with open("{}{}.json".format(LOGS_PATH, exploit_class), 'w') as fp:
			json.dump(logs, fp, indent=4)

	def generate(self, logs):
		print logs
		exploit_type = EXPLOIT_CLASS[logs["class"]]

		self.write_to_json(exploit_type, logs)

		for host, exploits in logs["results"].items():
			for exploit in exploits:
				file_name = "{}exploit_{}_{}.py".format(EXPLOIT_PATH, self.counter, exploit_type)
				fp = open(file_name, "w")
				fp.write("import urllib, urllib2, cookielib, webbrowser, os\n")
				url = host + exploit["endpoint"]
				if exploit["method"] == "GET":
					fp.write("url = '{}'\n".format(self.craft_get_url(url, exploit["params"])))
					fp.write("new = 2\n")
					fp.write("webbrowser.open(url, new)\n")
				elif exploit["method"] == "POST":
					fp.write('url = "'+url+'"\n')
					fp.write('values = '+str(exploit["params"])+'\n')
					fp.write('data = urllib.urlencode(values)\n')
					fp.write('req = urllib2.Request(url, data)\n')
					fp.write('rsp = urllib2.urlopen(req)\n')
					fp.write('content = rsp.read()\n')
					fp.write('tmp_file = "/tmp/tmp.html"\n')
					fp.write('fp = open(tmp_file, "w")\n')
					fp.write('fp.write(content)\n')
					fp.write('fp.close()\n')
					fp.write('webbrowser.open("file://" + os.path.realpath(tmp_file))\n')
				else:
					break
				fp.close()
				self.counter += 1
