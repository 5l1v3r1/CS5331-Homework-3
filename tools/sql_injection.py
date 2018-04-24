import httplib2
import itertools
import urllib
from urlparse import urljoin, urlparse
from helper import has_form, parse_form, post_request, get_request, create_post_params, create_get_params, log_results, has_get_params
from sets import Set

EXPLOIT_PATH = "exploits/"
EXPLOIT_TYPE = "sqli"
EXPLOIT_CLASS = "SQL Injection"

SQL_EXPLOIT_LIST = "tools/sql.txt"

class SQLIModule:
    """
    SQL Injection Module
    Checks for SQLI vulnerability
    """

    def __init__(self, url, pages):
        self.url = url
        self.pages = pages
        self.logs = {}

    # def craft_injection_form(self, forms):
    #     modifiable_form_input = []
    #     for form_input in forms:
    #         if form_input[0] != "csrftoken":
    #             modifiable_form_input.append(form_input[0])
    #     for i in range(len(forms)):
    #         combinations = list(itertools.combinations(modifiable_form_input,i+1))

    def scan(self):
        results = []
        get_param_pages = Set([])
        for web_page in self.pages:
            http = httplib2.Http()
            status, response = http.request(web_page)
            if has_form(response):
                forms = parse_form(response)
                original_response = post_request(web_page, forms)
                random_forms = []
                for form_input in forms:
                    if form_input[0] == "csrftoken": # We don't have incentive to change this
                        random_forms.append(form_input)
                    else:
                        random_forms.append((form_input[0], "absldkjf"))
                random_response = post_request(web_page, random_forms)

                sql_exploit_file = open(SQL_EXPLOIT_LIST, "r")
                sql_exploit_list = [x.strip() for x in sql_exploit_file.readlines()] 
                for exploit in sql_exploit_list:
                    malicious_forms = []
                    for form_input in forms:
                        if form_input[0] == "csrftoken": # We don't have incentive to change this
                            malicious_forms.append(form_input)
                        else:
                            malicious_forms.append((form_input[0], exploit))
                    new_response = post_request(web_page, malicious_forms)
                    if original_response != new_response and new_response != random_response: # That means that the webpage is different, possibly a successful case
                        results.append((urlparse(web_page).path, create_post_params(malicious_forms), "POST"))
                        break
            elif has_get_params(web_page) and urlparse(web_page).path not in get_param_pages:
                # GET version
                parsed_web_page = urlparse(web_page)
                get_param_pages.add(parsed_web_page.path)
                param_list = map(lambda x: x.split("="), parsed_web_page.query.split("&"))
                original_response = get_request(web_page)
                random_param_query = "?" + "&".join(map(lambda param: param[0] + "=" + urllib.quote("slkdfjsldk") ,param_list))
                random_url = parsed_web_page.scheme + "://" + parsed_web_page.netloc + parsed_web_page.path + random_param_query
                random_response = get_request(random_url)
                malicious_params = []
                sql_exploit_file = open(SQL_EXPLOIT_LIST, "r")
                sql_exploit_list = [x.strip() for x in sql_exploit_file.readlines()] 
                for exploit in  sql_exploit_list:
                    malicious_params = []
                    for param in param_list:
                        malicious_params.append((param[0], exploit))
                    malicious_param_query = "?" + "&".join(map(lambda malicious_param: malicious_param[0] + "=" + urllib.quote(malicious_param[1]), malicious_params))
                    malicious_url = parsed_web_page.scheme  + "://" + parsed_web_page.netloc + parsed_web_page.path + malicious_param_query
                    malicious_response = get_request(malicious_url)
                    if malicious_response != original_response and malicious_response != random_response: # That means that the webpage is different, possibly a successful case
                        results.append((urlparse(web_page).path, create_get_params(malicious_url), "GET"))

        self.logs = log_results(self.url, results, EXPLOIT_CLASS)
