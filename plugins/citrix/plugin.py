from core.env import SIGINT_handler
import signal
from core.logger import Output
from core.dnslookup import lookup
import requests

NAME        = 'citrix'
ARG_HELP    = 'Citrix Sharefile domain lookup'

handler = SIGINT_handler()
signal.signal(signal.SIGINT, handler.signal_handler)

def execute(**kwargs):
    if handler.SIGINT:
        Output().warn("Aborted plugin: %s" % NAME, False)
        return None
    try:
        domain = kwargs['domain'].split('.')
        config = kwargs['config']
        subfuz = kwargs['subfuz']
        citrix_targets = [domain[-2] + '.sharefile.com']
        redirect = requests.get('https://' + citrix_targets[0])
        if 'secure.sharefile.com' not in redirect.url:
            authlogin = redirect.url.split('/')[2]
            ans = lookup(authlogin, 'ANY', '8.8.8.8', 'UDP', subfuz.timeout)
            if ans:
                subfuz.parse_record(ans, authlogin)
                Output().neutral("Citrix sharefile found", False)
    except:
        raise
