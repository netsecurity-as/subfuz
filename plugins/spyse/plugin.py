import json, requests
from core.env import SIGINT_handler
import signal
from core.logger import Output

NAME        = 'spyse'
ARG_HELP    = 'Spyse subdomain'

handler = SIGINT_handler()
signal.signal(signal.SIGINT, handler.signal_handler)

class SpyseError(Exception):
   """Base class for Spyse exceptions"""
   pass

def execute(domain, config, **kwargs):
    if handler.SIGINT:
        Output().warn("Aborted plugin: %s" % NAME, False)
        return None
    try:
        max_pages = config['max_pages']
        d = []
        for page in range(1,max_pages):
            query = "https://api.spyse.com/v1/subdomains?api_token=%s&domain=%s&page=%s" % (config['api_token'], domain.rstrip(), page)
            r = requests.get(query)
            if r.status_code == 200:
                data = json.loads(r.content)
                if 'records' in data:
                    if len(data['records']) == 0:
                        break
                    for x in data['records']:
                        d.append(x['domain'])
                else:
                    return None
            elif r.status_code == 400:
                raise SpyseError('Maximum value for parameter exceeded / invalid or missing required parameters')
            elif r.status_code == 403:
                raise SpyseError('Missing or invalid required parameter api_token')
            elif r.status_code == 500:
                raise SpyseError('Internal server error')
            elif r.status_code == 402:
                raise SpyseError('Request limit exceeded')
            else:
                raise SpyseError('Spyse plugin: Unexpected Error')
        return set(d)
    except:
            raise
