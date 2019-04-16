from core.env import SIGINT_handler
import signal
from core.logger import Output
from core.dnslookup import lookup
import requests
from BeautifulSoup import BeautifulSoup

NAME        = 'dnsdumpster'
ARG_HELP    = 'Dnsdumpster by hackertarget'

handler = SIGINT_handler()
signal.signal(signal.SIGINT, handler.signal_handler)

def execute(**kwargs):
    if handler.SIGINT:
        Output().warn("Aborted plugin: %s" % NAME, False)
        return None
    try:
        domain = kwargs['domain']
        csrf_page = requests.get('https://dnsdumpster.com')
        soup = BeautifulSoup(csrf_page.content)
        csrf_token = soup.find('input', {'name': 'csrfmiddlewaretoken'}).get('value')
        query = requests.post('https://dnsdumpster.com', data = {'csrfmiddlewaretoken' : csrf_token, 'targetip' : domain},headers={'referer' : 'https://dnsdumpster.com/'}, cookies={ 'csrftoken' : csrf_token})
        soup = BeautifulSoup(query.content)
        sites = soup.findAll("td",attrs={"class": "col-md-4"})
        d = []
        for site in sites:
            d.append(site.text.split(domain)[0] + domain)
        return set(d)
    except:
        raise
