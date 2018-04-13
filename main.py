from tools.crawler import Crawler
from tools.sql_injection import SQLIModule
from tools.shell_injection import SCIModule

ORIGIN = 'http://target.com'


if __name__ == '__main__':
    crawler = Crawler(ORIGIN)
    pages = crawler.crawl()
    for page in pages:
        print page

    sqli_module = SQLIModule(ORIGIN, pages)
    sqli_module.scan()
    sqli_module.generate_exploits()

    sci_module = SCIModule(ORIGIN, pages)
    sci_module.scan()
    sci_module.generate_exploits()
