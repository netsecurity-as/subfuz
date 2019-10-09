import json, requests
from core.env import SIGINT_handler
import signal
from core.logger import Output

NAME        = 'censys'
ARG_HELP    = 'censys subdomain certificates'

handler = SIGINT_handler()
signal.signal(signal.SIGINT, handler.signal_handler)

class CENSYSError(Exception):
   """Base class for censys exceptions"""
   pass

def execute(domain, config, **kwargs):
    if handler.SIGINT:
        Output().warn("Aborted plugin: %s" % NAME, False)
        return None
    try:
        subdomains = []
        page = 1
        max_pages = config['max_page']
        while max_pages >= page:
            url = "https://censys.io/api/v1/search/certificates"
            payload = '{"query":"%s","page":%d,"fields":["parsed.names"],"flatten":true}' % (
            domain.rstrip(), page)
            r = requests.post(url, auth=(config['uid'], config['secret']), json=payload)
            if r.status_code == 403:
                raise CENSYSError('Censys plugin: Unauthorized / Invalid Credentials')
            elif r.status_code == 200:
                data = json.loads(r.content)
                page = data['metadata']['page'] + 1
                max_pages = min(data['metadata']['pages'], max_pages)
                for x in data['results']:
                    for y in x['parsed.names']:
                        subdomains.append(y.strip('*').strip('.'))
            else:
                raise CENSYSError('Censys plugin: Unknown error, HTTP status code: %d' % r.status_code)
        return set(subdomains)
    except:
        raise
