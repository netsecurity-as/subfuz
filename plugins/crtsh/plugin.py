import json, requests
from core.env import SIGINT_handler
import signal
from core.logger import Output

NAME        = 'crtsh'
ARG_HELP    = 'crt.sh subdomain certificates'

handler = SIGINT_handler()
signal.signal(signal.SIGINT, handler.signal_handler)

class CRTError(Exception):
   """Base class for crt.sh exceptions"""
   pass

def execute(domain, config):
    if handler.SIGINT:
        Output().warn("Aborted plugin: %s" % NAME, False)
        return None
    try:
        query = 'https://crt.sh/?q=%25.' + domain.rstrip() + '&output=json'
        r = requests.get(query)
        if r.status_code == 200:
            data = json.loads(r.content)
            d = []
            for x in data:
                d.append(x['name_value'].strip('*').strip('.'))
            return set(d)
        else:
            raise CRTError('crtsh plugin: Unexpected Error')
    except:
        raise
