import httplib2, urllib, urllib2
from BeautifulSoup import BeautifulSoup, SoupStrainer
from urlparse import urljoin, urlparse
from sets import Set


class Crawler:
    """
    Crawler Module
    Visits all pages available on target site, then returns list of all pages
    """
    
    def __init__(self, url):
        self.url = url
        self.visited = Set([])

    def same_origin(self, url1, url2):
        first_url = urlparse(url1)
        second_url = urlparse(url2)
        return first_url.scheme == second_url.scheme and first_url.netloc == second_url.netloc and first_url.port == second_url.port

    def visit_url(self, url):
        http = httplib2.Http()
        status, response = http.request(url)
        links = []
        for link in BeautifulSoup(response, parseOnlyThese=SoupStrainer('a')):
            if link.has_key('href'):
                links.append((url, link['href']))
        return links

    def recurse(self, start, origin):
        stack = [(origin,start)]
        while len(stack) != 0:
            current_origin, current_start = stack.pop()
            current_url = urljoin(current_origin, current_start)
            if self.same_origin(current_url, self.url) and current_url not in self.visited:
                self.visited.add(current_url)
                new_urls = self.visit_url(current_url)
                stack = new_urls + stack

    def crawl(self):
        self.recurse(self.url, self.url)
        pages_list = list(self.visited)
        pages_list.sort()
        return pages_list
