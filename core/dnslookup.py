import dns.name
import dns.message
import dns.query
import dns.flags
import dns.rdatatype
import dns.reversename
from socket import gethostbyname_ex


# acceptable request types:
""" ['A', 'A6', 'AAAA', 'AFSDB', 'ANY', 'APL', 'AVC', 'AXFR', 'CAA', 'CDNSKEY', 'CDS', 'CERT', 'CNAME',
    'CSYNC', 'DHCID', 'DLV', 'DNAME', 'DNSKEY', 'DS', 'EUI48', 'EUI64', 'GPOS', 'HINFO', 'HIP', 'IPSECKEY',
    'ISDN', 'IXFR', 'KEY', 'KX', 'LOC', 'MAILA', 'MAILB', 'MB', 'MD', 'MF', 'MG', 'MINFO', 'MR', 'MX',
    'NAPTR', 'NONE', 'NS', 'NSAP', 'NSAP_PTR', 'NSEC', 'NSEC3', 'NSEC3PARAM', 'NULL', 'NXT', 'OPT', 'PTR',
    'PX', 'RP', 'RRSIG', 'RT', 'SIG', 'SOA', 'SPF', 'SRV', 'SSHFP', 'TA', 'TKEY', 'TLSA', 'TSIG', 'TXT',
    'UNSPEC', 'URI', 'WKS', 'X25'] """

class ProtocolError(Exception):
    pass

def lookup(domain, type='ANY', nameserver='8.8.8.8', protocol='UDP', dnstimeout=2):
    domain = domain.encode('idna').decode('utf-8')
    if type == 'PTR':
        domain = dns.reversename.from_address(domain).to_text()
    nameserver = gethostbyname_ex(nameserver.encode('idna'))[2][0]
    ADDITIONAL_RDCLASS = 65535
    try:
        request = dns.message.make_query(domain, getattr(dns.rdatatype, type))
    except Exception:
        return False
    request.flags |= dns.flags.AD
    request.find_rrset(request.additional, dns.name.root, ADDITIONAL_RDCLASS, dns.rdatatype.OPT, create=True, force_unique=True)
    
    try:
        if protocol == 'TCP':
            return dns.query.tcp(request, nameserver, timeout=dnstimeout).answer
        elif protocol == 'UDP':
            return dns.query.udp(request, nameserver, timeout=dnstimeout).answer
        else:
            raise ProtocolError("Invalid Protocol", -1)
    except Exception:
        return False

