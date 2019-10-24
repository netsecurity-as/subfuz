import json, requests
from core.env import SIGINT_handler
import signal
from core.logger import Output

NAME        = 'securitytrails'
ARG_HELP    = 'securitytrails subdomain'

handler = SIGINT_handler()
signal.signal(signal.SIGINT, handler.signal_handler)

class securitytrailsError(Exception):
   """Base class for securitytrails exceptions"""
   pass

def execute(domain, config, **kwargs):
    if handler.SIGINT:
        Output().warn("Aborted plugin: %s" % NAME, False)
        return None
    try:
        d = []
        query = "https://api.securitytrails.com/v1/domain/%s/subdomains?apikey=%s" % (domain.rstrip(),config['apikey'])
        r = requests.get(query)
        if r.status_code == 200:
            data = json.loads(r.content)
            for x in data['subdomains']:
                subdomain = x + "." + domain.rstrip()
                d.append(subdomain)
        elif r.status_code == 400:
            raise securitytrailsError('400 - Bad request')
        elif r.status_code == 401:
            raise securitytrailsError('401 - Unauthorized')
        elif r.status_code == 403:
            raise securitytrailsError('403 - Forbidden')
        elif r.status_code == 429:
            raise securitytrailsError('429 - Too many requests')
        elif r.status_code == 500:
            raise securitytrailsError('500 - Internal Server Error')
        else:
            raise securitytrailsError('securitytrails plugin: Unexpected Error')
        return set(d)
    except:
        raise
