import requests, re
from core.env import SIGINT_handler
import signal
from core.logger import Output


NAME        = 'fsd'
ARG_HELP    = 'findsubdomains.com subdomains'

handler = SIGINT_handler()
signal.signal(signal.SIGINT, handler.signal_handler)

class FSDError(Exception):
   """Base class for fsd exceptions"""
   pass

def execute(domain, **kwargs):
    if handler.SIGINT:
        Output().warn("Aborted plugin: %s" % NAME, False)
        return None
    try:
        query = 'https://findsubdomains.com/subdomains-of/' + domain.rstrip()
        r = requests.get(query)
        bRep = r.text #response body
        if r.status_code == 200:
                d = []
                lines = bRep.split("\n")
                for x in lines:
                    #we want<a href="/subdomains-of/admin.test.no" class="aggregated-link mobile-hidden">admin.test.no</a>
                    #but not <a class="aggregated-link mobile-hidden" rel="nofollow" href="/subdomains-of/{{:domain}}" target="_blank">
                    if "aggregated-link mobile-hidden" in x:
                        if "rel=\"nofollow\"" in x:
                            continue
                        subdom = re.split('<|>',x)
                        d.append(subdom[2])
                return set(d)
        else:
            raise FSDError('fsd plugin: Unexpected Error')
    except:
        raise
