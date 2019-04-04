from core.env import SIGINT_handler
import signal
from core.logger import Output
from core.dnslookup import lookup
import requests
import json

NAME        = 'circl'
ARG_HELP    = 'CIRCL Passive DNS is a database storing historical records'

handler = SIGINT_handler()
signal.signal(signal.SIGINT, handler.signal_handler)

def execute(**kwargs):
    if handler.SIGINT:
        Output().warn("Aborted plugin: %s" % NAME, False)
        return None
    try:
        domain = kwargs['domain']
        config = kwargs['config']
        auth = requests.auth.HTTPBasicAuth(config['user'], config['pass'])
        r = requests.get('https://www.circl.lu/pdns/query/' + domain, auth=auth)
        if r.status_code ==  200 and r.text:
            json_page = '[' + r.text.replace('}\n{','},{') + ']'
            data = json.loads(json_page)
            d = []
            for x in data:
                d.append(x['rdata'])
            return set(d)
    except:
        raise
