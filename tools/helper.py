# helper.py
# generic GET and POST queries

import urllib, urllib2
from BeautifulSoup import BeautifulSoup, SoupStrainer

def has_form(html_page):
    return len(BeautifulSoup(html_page, parseOnlyThese=SoupStrainer('form'))) != 0

def get_form_action(html_page):
    soup = BeautifulSoup(html_page)
    form = soup.find('form')
    return soup.find('form').get('action')

def parse_form(html_page):
    soup = BeautifulSoup(html_page)
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

def create_post_params(params):
    values = {}
    for attr in params:
        if attr[1] == "":
            values[attr[0]] = "a"
        else:
            values[attr[0]] = attr[1]
    return values

def create_get_params(url):
    values = {}
    params = url.split("?")[1].split("&")
    for param in params:
        attr = param.split("=")
        if attr[1] == "":
            values[attr[0]] = "a"
        else:
            values[attr[0]] = attr[1]
    return values

def post_request(url, params):
    values = create_post_params(params)
    data = urllib.urlencode(values)
    req = urllib2.Request(url, data)
    rsp = urllib2.urlopen(req)
    return rsp.read()