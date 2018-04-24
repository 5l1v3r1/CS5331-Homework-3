import httplib2, urllib, urllib2
from BeautifulSoup import BeautifulSoup, SoupStrainer
from urlparse import urljoin, urlparse
from helper import has_form, parse_form, post_request, create_get_params, log_results
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

    def replace_parameters(self, url):
        url_param = url.split("?")
        if len(url_param) > 1:
            params = url_param[1].split("&")
            for x in xrange(len(params)):
                param = params[x]
                new_param = param.split("=")[0] + "=" + "https://status.github.com/messages"
                params[x] = new_param
            return url.split("?")[0] + "?" + "&".join(params)
        else:
            return url

    def same_origin(self, url1, url2):
        first_url = urlparse(url1)
        second_url = urlparse(url2)
        return first_url.scheme == second_url.scheme and first_url.netloc == second_url.netloc and first_url.port == second_url.port

    def scan(self):
        results = []
        for web_page in self.pages:
            http = httplib2.Http()
            response, content = http.request(web_page)
            new_page = self.replace_parameters(web_page)
            new_response, new_content = http.request(new_page)
            if not self.same_origin(response['content-location'], new_response['content-location']):
                results.append((urlparse(new_page).path, create_get_params(new_page), "GET"))
        self.logs = log_results(self.url, results, EXPLOIT_CLASS)
