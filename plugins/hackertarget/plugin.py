import json, requests, io
from core.env import SIGINT_handler
import signal
from core.logger import Output

NAME        = 'hackertarget'
ARG_HELP    = 'hackertarget subdomains'

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
        query = 'https://api.hackertarget.com/hostsearch/?q=' + domain.rstrip()
        r = requests.get(query)
        bRep = r.text #response body
        if r.status_code == 200:
            if "error check your search parameter" not in bRep:
                d = []
                lines = bRep.split("\n")
                for x in lines:
                    subdom = x.split(',')
                    d.append(subdom[0])
                return set(d)
        else:
            raise CRTError('hackertarget plugin: Unexpected Error')
    except:
        raise
