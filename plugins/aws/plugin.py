from core.env import SIGINT_handler
import signal
from core.logger import Output
from core.dnslookup import lookup
import requests

NAME        = 'aws'
ARG_HELP    = 'Amazon S3 bucket lookup'

handler = SIGINT_handler()
signal.signal(signal.SIGINT, handler.signal_handler)

def execute(**kwargs):
    if handler.SIGINT:
        Output().warn("Aborted plugin: %s" % NAME, False)
        return None
    try:
        subfuz = kwargs['subfuz']
        domain = kwargs['domain'].split('.')
        aws_target = [domain[-2] + '.s3.amazonaws.com'][0]
        query = requests.get('https://' + aws_target)
        if query.status_code == 404:
            return None
        elif query.status_code == 200:
            Output().good('Bucket %s is open' % aws_target,False)
        ans = lookup(aws_target.encode('utf-8'), 'ANY', '8.8.8.8', 'UDP', subfuz.timeout)
        if ans:
            subfuz.parse_record(ans, aws_target)
    except:
        raise
