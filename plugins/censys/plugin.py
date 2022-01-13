from censys.search import CensysCertificates
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
        c = CensysCertificates(api_id=config['uid'], api_secret=config['secret'])
        fields = [
            "parsed.names",
            "parsed.subject.common_name",
            "parsed.extensions.subject_alt_name.dns_names"
        ]
        results = []
        for page in c.search(domain, fields, max_records=config['max_records']):
            results.append(page)
        #Flatten json to array
        list = []
        for x in results:
            if x.get('parsed.namesn'):
                list += (x.get('parsed.names'))
            
            if x.get('parsed.subject.common_name'):
                list += x.get('parsed.subject.common_name')
            
            if x.get('parsed.extensions.subject_alt_name.dns_names'):
                list += x.get('parsed.extensions.subject_alt_name.dns_names')

        subdomains = []
        for x in list:
            subdomains.append(x.lstrip('*').lstrip('.'))
        subdomains = sorted(set(subdomains))
        return subdomains
    except Exception as E:
        print (E)
        raise
