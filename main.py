from tools.crawler import Crawler
from tools.sql_injection import SQLIModule
from tools.shell_injection import SCIModule
from tools.open_redirect import ORModule
from tools.generator import ExploitGenerator

ORIGIN = 'http://target.com'


if __name__ == '__main__':
    # CRAWL TARGET HOST
    crawler = Crawler(ORIGIN)
    exploit_generator = ExploitGenerator()
    pages = crawler.crawl()

    # SCAN SQL INJECTION
    sqli_module = SQLIModule(ORIGIN, pages)
    sqli_module.scan()
    exploit_generator.generate(sqli_module.logs)

    # SCAN SERVER SIDE CODE INJECTION

    # SCAN DIRECTORY TRAVERSAL 

    # SCAN OPEN REDIRECT
    or_module = ORModule(ORIGIN, pages)
    or_module.scan()
    exploit_generator.generate(or_module.logs)

    # SCAN CSRF

    # SCAN SHELL CODE INJECTION
    sci_module = SCIModule(ORIGIN, pages)
    sci_module.scan()
    exploit_generator.generate(sci_module.logs)
