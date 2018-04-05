import httplib2
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

if __name__ == '__main__':
    crawl(ORIGIN, ORIGIN)
    results = list(visited)
    results.sort()
    print(results)