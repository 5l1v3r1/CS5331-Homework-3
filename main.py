import scrapy

from scrapy.crawler import CrawlerProcess
from sets import Set
from urlparse import urljoin, urlparse

from tools.sql_injection import SQLIModule
from tools.shell_injection import SCIModule
from tools.open_redirect import ORModule
from tools.directory_traversal import DTModule
from tools.generator import ExploitGenerator


EXPLOIT_SQLI = "SQL Injection"
EXPLOIT_SSCI = "Server Side Code Injection"
EXPLOIT_DT = "Directory Traversal"
EXPLOIT_OR = "Open Redirect"
EXPLOIT_CSRF = "CSRF"
EXPLOIT_CI = "Command Injection"

ORIGINS = [
  'http://target.com', # TARGET 1
  # '', # TARGET 2
  # '', # TARGET 3
]
ORIGIN = ''
VISITED = None


class Main:

    def __init__(self):
        self.sqli = self.init_logs(EXPLOIT_SQLI)
        self.ssci = self.init_logs(EXPLOIT_SSCI)
        self._dt = self.init_logs(EXPLOIT_DT)
        self._or = self.init_logs(EXPLOIT_OR)
        self.csrf = self.init_logs(EXPLOIT_CSRF)
        self._ci = self.init_logs(EXPLOIT_CI)
        self.generator = ExploitGenerator()

    def generate_and_write_to_file(self):
        self.generator.generate(self.sqli)
        self.generator.generate(self.ssci)
        self.generator.generate(self._dt)
        self.generator.generate(self._or)
        self.generator.generate(self.csrf)
        self.generator.generate(self._ci)

    def init_logs(self, exploit_class):
        return {
            "class": exploit_class,
            "results": {
            }
        }

    def append_logs(self, logs):
        exploit_class = logs["class"]
        if exploit_class == EXPLOIT_SQLI:
            dict_one = self.sqli["results"]
            dict_two = logs["results"]
            self.sqli["results"] = self.merge_two_dict(dict_one, dict_two)
        elif exploit_class == EXPLOIT_SSCI:
            dict_one = self.ssci["results"]
            dict_two = logs["results"]
            self.ssci["results"] = self.merge_two_dict(dict_one, dict_two)
        elif exploit_class == EXPLOIT_DT:
            dict_one = self._dt["results"]
            dict_two = logs["results"]
            self._dt["results"] = self.merge_two_dict(dict_one, dict_two)
        elif exploit_class == EXPLOIT_OR:
            dict_one = self._or["results"]
            dict_two = logs["results"]
            self._or["results"] = self.merge_two_dict(dict_one, dict_two)
        elif exploit_class == EXPLOIT_CSRF:
            dict_one = self.csrf["results"]
            dict_two = logs["results"]
            self.csrf["results"] = self.merge_two_dict(dict_one, dict_two)
        elif exploit_class == EXPLOIT_CI:
            dict_one = self._ci["results"]
            dict_two = logs["results"]
            self._ci["results"] = self.merge_two_dict(dict_one, dict_two)

    def merge_two_dict(self, dict_one, dict_two):
        result = dict_one.copy()
        result.update(dict_two)
        return result


class ScrapyCrawler(scrapy.Spider):
    name = "ScrapyCrawler"

    def __init__(self):
        self.origin = ORIGIN
        self.start_urls = [self.origin]

    def same_origin(self, url1, url2):
        first_url = urlparse(url1)
        second_url = urlparse(url2)
        return first_url.scheme == second_url.scheme and first_url.netloc == second_url.netloc and first_url.port == second_url.port

    def parse(self, response):
        SELECTOR = 'a'

        current_origin = response.request.url
        urls = response.css('a::attr(href)').extract()

        for next_url in urls:
            # IF next_url exists
            if next_url is not None:
                next_url = urljoin(current_origin, next_url)

                # Check that url is not visited yet
                if self.same_origin(next_url, self.origin) and next_url not in VISITED:
                    VISITED.add(next_url)
                    yield scrapy.Request(next_url, cookies={}, callback=self.parse)


if __name__ == '__main__':
    main = Main()

    # PROBE EACH TARGET WITH ALL MODULES
    for target in ORIGINS:
        # SET UP GLOBAL VARIABLE
        ORIGIN = target
        VISITED = Set([ORIGIN])

        # INIT SPIDER PROCESS
        scrapy_crawler = ScrapyCrawler()
        process = CrawlerProcess()
        process.crawl(scrapy_crawler)
        process.start()

        # CLEAN UP VISITED
        pages = list(VISITED)
        pages.sort()

        # SCAN SQL INJECTION
        sqli_module = SQLIModule(target, pages)
        sqli_module.scan()
        main.append_logs(sqli_module.logs)

        # SCAN SERVER SIDE CODE INJECTION

        # SCAN DIRECTORY TRAVERSAL
        dt_module = DTModule(target, pages)
        dt_module.scan()
        main.append_logs(dt_module.logs)

        # SCAN OPEN REDIRECT
        or_module = ORModule(target, pages)
        or_module.scan()
        main.append_logs(or_module.logs)

        # SCAN CSRF

        # SCAN SHELL CODE INJECTION
        sci_module = SCIModule(target, pages)
        sci_module.scan()
        main.append_logs(sci_module.logs)

    # DONE PROBING, GENERATE ALL LOGS
    main.generate_and_write_to_file()
