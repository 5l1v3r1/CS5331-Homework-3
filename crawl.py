import scrapy

from scrapy.crawler import CrawlerProcess
from sets import Set
from urlparse import urljoin, urlparse

from tools.sql_injection import SQLIModule
from tools.shell_injection import SCIModule
from tools.open_redirect import ORModule
from tools.directory_traversal import DTModule
from tools.generator import ExploitGenerator

ORIGIN = 'http://target.com'
VISITED = Set([])

class ScrapyCrawler(scrapy.Spider):
  name = "ScrapyCrawler"

  def __init__(self):
    self.origin = ORIGIN
    self.start_urls = [self.origin]
    self.visited = Set([])

  def same_origin(self, url1, url2):
    first_url = urlparse(url1)
    second_url = urlparse(url2)
    return first_url.scheme == second_url.scheme and first_url.netloc == second_url.netloc and first_url.port == second_url.port

  def parse(self, response):
    SELECTOR = 'a'

    urls = response.css('a::attr(href)').extract()

    for next_url in urls:
      # IF next_url exists
      if next_url is not None:
        next_url = urljoin(self.origin, next_url)

        # Check that url is not visited yet
        if self.same_origin(next_url, self.origin) and next_url not in VISITED:
          VISITED.add(next_url)
          print len(VISITED)
          yield scrapy.Request(next_url, callback=self.parse)

if __name__ == '__main__':
  scrapy_crawler = ScrapyCrawler()
  process = CrawlerProcess()
  process.crawl(scrapy_crawler)
  process.start()

  pages = list(VISITED)
  pages.sort()
  exploit_generator = ExploitGenerator()

  # SCAN SQL INJECTION
  sqli_module = SQLIModule(ORIGIN, pages)
  sqli_module.scan()
  exploit_generator.generate(sqli_module.logs)

  # SCAN SERVER SIDE CODE INJECTION

  # SCAN DIRECTORY TRAVERSAL
  dt_module = DTModule(ORIGIN, pages)
  dt_module.scan()
  exploit_generator.generate(dt_module.logs)

  # SCAN OPEN REDIRECT
  or_module = ORModule(ORIGIN, pages)
  or_module.scan()
  exploit_generator.generate(or_module.logs)

  # SCAN CSRF

  # SCAN SHELL CODE INJECTION
  sci_module = SCIModule(ORIGIN, pages)
  sci_module.scan()
  exploit_generator.generate(sci_module.logs)
