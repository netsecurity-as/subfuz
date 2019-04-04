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
        domain = kwargs['domain'].split('.')
        config = kwargs['config']
        aws_targets = [domain[-2] + '.s3.amazonaws.com']
        query = requests.get('https://' + aws_targets[0])
        if query.status_code == 404:
            return None
        if query.status_code == 403:
            bucket = aws_targets[0]
            ans = lookup(bucket.encode('utf-8'), 'ANY', '8.8.8.8', 'UDP', subfuz.timeout)
        if query.status_code == 200:
            bucket = aws_targets[0]
            Output().good('Bucket %s is open' % bucket,False)
            ans = lookup(bucket.encode('utf-8'), 'ANY', '8.8.8.8', 'UDP', subfuz.timeout)
        if ans:
           subfuz.parse_record(ans, bucket)
    except:
        raise
