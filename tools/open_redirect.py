import httplib2, urllib, urllib2
from BeautifulSoup import BeautifulSoup, SoupStrainer
from urlparse import urljoin, urlparse
from sets import Set

EXPLOIT_PATH = "exploits/"
EXPLOIT_TYPE = "or"
EXPLOIT_CLASS = "Open Redirect"


class ORModule:
    """
    Open Redirect Module
    Checks for Open Redirect vulnerability
    """

    def __init__(self, url, pages):
        self.url = url
        self.pages = pages
        self.logs = {}

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

    def replace_parameters(self, url):
        url_param = url.split("?")
        if len(url_param) > 1:
            params = url_param[1].split("&")
            for x in xrange(len(params)):
                param = params[x]
                new_param = param.split("=")[0] + "=" + "http://www.google.com"
                params[x] = new_param
            return url.split("?")[0] + "?" + "&".join(params)
        else:
            return url

    def same_origin(self, url1, url2):
        first_url = urlparse(url1)
        second_url = urlparse(url2)
        return first_url.scheme == second_url.scheme and first_url.netloc == second_url.netloc and first_url.port == second_url.port

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
                elif vuln["method"] == "GET":
                    # TODO: Finish this part
                    fp.write("url = '"+vuln["endpoint"]+"'\n")
                    fp.write("new = 2\n")
                    fp.write("webbrowser.open(url, new)\n")
                fp.close()
                counter += 1

    def scan(self):
        results = []
        for web_page in self.pages:
            http = httplib2.Http()
            response, content = http.request(web_page)
            new_page = self.replace_parameters(web_page)
            new_response, new_content = http.request(new_page)
            if not self.same_origin(response['content-location'], new_response['content-location']):
                results.append((new_page, {}, "GET"))
        self.logs = self.log_results(results, EXPLOIT_CLASS)
