from core.env import SIGINT_handler
import signal
from core.logger import Output
from core.dnslookup import lookup

NAME        = 'microsoft'
ARG_HELP    = 'Microsoft tenant domain lookup'

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
        ms_targets = [domain[-2] + '.sharepoint.com',
                      domain[-2] + '-my.sharepoint.com',
                      domain[-2] + '-myfiles.sharepoint.com',
                      domain[-2] + '-files.sharepoint.com',
                      domain[-2] + '.onmicrosoft.com',
                      '%s-%s.mail.protection.outlook.com' % (domain[-2], domain[-1])]
        for ms in ms_targets:
            ans = lookup(ms.encode('utf-8'), 'ANY', '8.8.8.8', 'UDP', subfuz.timeout)
            if ans:
                subfuz.parse_record(ans, ms)
    except:
        raise
