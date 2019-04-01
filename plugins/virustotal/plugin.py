import json, requests
from core.env import SIGINT_handler
import signal
from core.logger import Output

NAME        = 'virustotal'
ARG_HELP    = 'VirusTotal subdomain certificates'

handler = SIGINT_handler()
signal.signal(signal.SIGINT, handler.signal_handler)

class VTError(Exception):
   """Base class for Virus Total exceptions"""
   pass

def execute(domain, config, **kwargs):
    if handler.SIGINT:
        Output().warn("Aborted plugin: %s" % NAME, False)
        return None
    try:
        query = "https://www.virustotal.com/vtapi/v2/domain/report?apikey=%s&domain=%s" % (config['api-key'], domain.rstrip())
        r = requests.get(query)
        if r.status_code == 200:
            data = json.loads(r.content)
            if 'subdomains' in data:
                # data should always be returned as a array
                return data['subdomains']
            else:
                return None
        elif r.status_code == 403:
            raise VTError('Virustotal plugin: API Unauthorized')
        else:
            raise VTError('Virustotal plugin: Unexpected Error')
    except:
        raise
