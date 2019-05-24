from dnslookup import lookup
from logger import Output, col
from threading import Thread, Lock
from env import SIGINT_handler
import time, signal, math
import random, string, sys, io, re
import dns.zone

class ScanList():
    def __init__(self, args):
        if args.dictionary:
            try:
                self.unscanned = map(unicode.strip, io.open(args.dictionary, encoding='utf-8', mode='r').readlines())
            except IOError as e:
                print (e)
                sys.exit()
        else:
            self.unscanned = []
        self.unscanned.insert(0,'')
        self.scanned = []
        self.found = []
        self.n_unscanned = len(self.unscanned)
        self.n_scanned = len(self.scanned)
        self.items = []
        self.subnets = []
        self.ptr_unscanned_ip = []
        self.ptr_scanned = 0
        self.scan_failed = []
        self.failcounter = 0


class SubFuz():
    def __init__(self, domain, config, args, PLUGINS_DIR, CORE_DIR):
        self.handler = SIGINT_handler()
        signal.signal(signal.SIGINT, self.handler.signal_handler)
        self.log = Output(args.log_filename, args.csv_filename, config['config']['error_file'], args.quiet)
        self.domain = domain.decode('utf-8').encode('idna')
        self.throttle = args.z / 1000.0
        self.threads = args.t
        self.zone = args.zone
        self.retry = config['config']['retry']
        if args.deep: self.deep_domains = map(unicode.strip, io.open(args.deep, encoding='utf-8', mode='r').readlines())
        else: self.deep_domains = config["config"]["deep_domains"]
        self.timeout = args.p
        if args.dns: self.dns = args.dns
        else: self.dns = config['config']['dns_fallback']
        if args.protocol: self.protocol = args.protocol
        else: self.protocol = config['config']['dns_fallback_protocol']
        self.protocol = self.protocol.upper()
        if args.record: self.record = args.record
        else: self.record = config['config']['dns_fallback_record']
        self.args = args
        self.config = config
        # TODO move wildcards to ScanList
        self.a_wildcard = self.aaaa_wildcard = self.txt_wildcard = self.mx_wildcard = self.cname_wildcard = []
        self.sl = ScanList(args)
        # Mutex lock required to avoid issues with multiple threads working on the same object.
        self.mutex = Lock()

        self.f1 = '{:50}'
        self.f2 = '{:8}'
        self.f3 = '{:10}'
        self.f4 = '{:46}'

    def dns_server(self):
        # If dns override is not specified
        dns_servers = []
        if not self.args.dns:
            ns_record = lookup(self.domain, 'NS', self.config['config']['dns_fallback'], self.protocol, self.timeout)
            if not ns_record:
                ns_record = lookup(".".join(self.domain.split('.')[-2:]), 'NS', self.config['config']['dns_fallback'], self.protocol, self.timeout)
                # TODO very ugly way of doing it, https://publicsuffix.org/list/public_suffix_list.dat is on the to-do list
                # currently doesn't handle target domain inputs like subdomain.domain.co.uk or similar domains very well yet.
                if not ns_record:  # Exit early if ns_record is not found.
                    self.log.fatal('Unabel to lookup NS server', False)
                    sys.exit()
            nameservers = [x for x in ns_record if x.rdtype == 2]
            if nameservers:
                self.log.normal('Name Servers:', True)
                # For every NS record found
                for y in nameservers[0]:
                    dns_server_name = y.target.to_text()
                    # get DNS server IP
                    try:
                        dns_servers.append(
                            [lookup(dns_server_name,'A', self.config['config']['dns_fallback'], self.protocol, self.timeout)[0].items[0].to_text(),
                             y.target.to_text()])
                    except:
                        self.log.fatal(self.f4.format(dns_server_name) + '{:15}'.format('Unabel to resolv DNS server - Likely due to unstable network connection'), False)
                        sys.exit()
            else:
                self.log.warn('No Name Servers found for %s' % self.domain, True)
                sys.exit()
        else:
            dns_servers.append([self.args.dns, self.args.dns])
        # Zone transfer
        for dns_server in dns_servers:
            if self.zone:
                try:
                    z = dns.zone.from_xfr(dns.query.xfr(dns_server[0], self.domain, timeout=10, lifetime=10))
                    self.log.good(self.f4.format(dns_server[1]) + '{:15}'.format(dns_server[0]) + ' - Zone Transfer allowed.', True)
                    names = z.nodes.keys()
                    for n in names:
                        self.log.normal(z[n].to_text(n), True)
                except:
                    self.log.warn(
                        self.f4.format(dns_server[1]) + '{:15}'.format(dns_server[0]) + ' - Zone Transfer not allowed.', True)
            else:
                self.log.neutral(self.f4.format(dns_server[1]) + '{:15}'.format(dns_server[0]), True)

            # Testing for open TCP and UDP ports for DNS servers, and what type of records are permitted.
            # TCP - ANY
            dns_result = []
            start = time.time()
            tany = lookup(self.domain, 'ANY', dns_server[0], 'TCP', self.timeout)
            end = time.time()
            if tany:
                if [x for x in tany if x.rdtype == 1 or x.rdtype == 28 or x.rdtype == 5 or x.rdtype == 15 or x.rdtype == 16]:
                    dns_result.append(['TCP', dns_server[0], 'ANY', end - start])
            # TCP - A
            start = time.time()
            ta = lookup(self.domain, 'A', dns_server[0], 'TCP', self.timeout)
            end = time.time()
            if ta:
                if [x for x in ta if x.rdtype == 1]:
                    dns_result.append(['TCP', dns_server[0], 'A', end - start])
            # UDP - ANY
            start = time.time()
            uany = lookup(self.domain, 'ANY', dns_server[0], 'UDP', self.timeout)
            end = time.time()
            if uany:
                if [x for x in uany if x.rdtype == 1 or x.rdtype == 28 or x.rdtype == 5 or x.rdtype == 15 or x.rdtype == 16]:
                    dns_result.append(['UDP', dns_server[0], 'ANY', end - start])
            # UDP - A
            start = time.time()
            ua = lookup(self.domain, 'A', dns_server[0], 'UDP', self.timeout)
            end = time.time()
            if ua:
                if [x for x in ua if x.rdtype == 1]:
                    dns_result.append(['UDP', dns_server[0], 'A', end - start])


        # Figure out the best combination to use
        dns_result = sorted(dns_result, key=lambda x: (x[3], x[1], x[0], x[2]))
        a = [i for i in dns_result if i[0] == 'UDP' and i[2] == 'ANY']
        b = [i for i in dns_result if i[0] == 'TCP' and i[2] == 'ANY']
        c = [i for i in dns_result if i[0] == 'UDP' and i[2] == 'A']
        d = [i for i in dns_result if i[0] == 'TCP' and i[2] == 'A']

        if a:  # ANY + UDP
            self.dns, self.protocol, self.record, delay = a[0][1], a[0][0], a[0][2], a[0][3]
        elif b:  # ANY + TCP
            self.dns, self.protocol, self.record, delay = b[0][1], b[0][0], b[0][2], b[0][3]
        elif c:  # A + UDP
            self.dns, self.protocol, self.record, delay = c[0][1], c[0][0], c[0][2], c[0][3]
        elif d:  # A + TCP
            self.dns, self.protocol, self.record, delay = d[0][1], d[0][0], d[0][2], d[0][3]


        # Compensate for override
        override_dns = self.args.dns
        override_record = self.args.record
        override_protocol = self.args.protocol
        if override_record: self.record = override_record
        if override_dns: self.dns = override_dns
        if override_protocol: self.protocol = override_protocol
        self.log.neutral('Using nameserver %s, query type %s over %s with RTT of %.4f seconds' % (self.dns, self.record, self.protocol, delay), True)


    def check_wildcard(self, domain_addr):
        try:
            wildcard = ''.join(random.choice(string.ascii_lowercase) for _ in range(15))
            ans = lookup( (wildcard + '.' + domain_addr.encode('utf-8')), self.record, self.dns, self.protocol, self.timeout)
            if ans:
                wc = False
                d = domain_addr.encode('utf-8')
                for r in ans:
                    if r.rdtype == 1:  # A RECORD
                        item = []
                        for x in r.items:
                            item.append(x.to_text())
                        self.a_wildcard += item
                        self.log.warn(self.f1.format("Wildcard A record found for %s: " % d) + ", ".join(item), True)
                        wc = True

                    if r.rdtype == 5:  # CNAME RECORD
                        item = []
                        for x in r.items:
                            item.append(x.to_text())
                        self.cname_wildcard += item
                        self.log.warn(self.f1.format("Wildcard CNAME record found for %s: " % d) + ", ".join(item), True)
                        wc = True

                    if r.rdtype == 16:  # TXT RECORD
                        item = []
                        for x in r.items:
                            item.append(x.to_text())
                        self.txt_wildcard += item
                        self.log.warn(self.f1.format("Wildcard TXT record found for %s: " % d) + ", ".join(item), True)
                        wc = True

                    if r.rdtype == 28:  # AAAA RECORD
                        item = []
                        for x in r.items:
                            item.append(x.to_text())
                        self.aaaa_wildcard += item
                        self.log.warn(self.f1.format("Wildcard AAAA record found for %s: " % d) + ", ".join(item), True)
                        wc = True

                    if r.rdtype == 15:  # MX RECORD
                        item = []
                        for x in r.items:
                            item.append(x.to_text())
                        self.mx_wildcard += item
                        self.log.warn(self.f1.format("Wildcard MX record found for %s: " % d) + ", ".join(item), True)
                        wc = True
                    if wc == True: return True
                #if not wc:
                #    return False
        except Exception as e:
            self.log.fatal(('Wildcard check on %s.' % domain_addr), False)
            print (e)
        return False


    def execute_plugins(self, plugins, self_class):
        for name, value in self.args._get_kwargs():
            for plugin in plugins:
                if (value is True or self.args.all) and name is plugin.NAME:
                    try:
                        plugin_conf = self.config['plugins'][plugin.NAME]
                        self.log.good('Executing plugin: %s' % name, True)
                        subdomains = plugin.execute(domain = self.domain, config = plugin_conf, subfuz = self_class)
                        if subdomains:
                            for d in subdomains:
                                self.new_targets(d.lower())
                    except Exception as e:
                        self.log.fatal(str(e), True)
                            # TODO: domains causes output clutter that is wildcard related.


    def scan(self):
        self.log.normal('\n\n' + self.f1.format('Domain Name') + self.f2.format('Record') + 'Value', True)
        self.log.normal('------------------------------------------------------', True)
        threads = []
        for i in range(self.threads):
            t = Thread(target=self.scan_worker)
            threads.append(t)
            t.start()
        while any(t.is_alive() for t in threads):
            if sys.stdout.isatty() and not self.args.quiet:
                self.log.printer()
                total = self.sl.n_unscanned + self.sl.n_scanned
                percentage = math.ceil(self.sl.n_scanned+0.0)/total*100
                sys.stdout.write("Status: " + col.cyan + "%d/%d " %(self.sl.n_scanned, total) + col.end + "domains tested. "
                                 + col.brown + "%.2f%%" % percentage + col.end + " done. failed: " + col.red +"%d" %
                                 self.sl.failcounter + col.end + " \r")
                sys.stdout.flush()
            time.sleep(0.05)
        self.log.printer()
        if not self.args.quiet: sys.stdout.write(' ' * 64 + '\n')
        return


    def append_target(self, subdomain):
        try:
            if subdomain not in self.sl.scanned and subdomain not in self.sl.unscanned:
                self.sl.unscanned.insert(0,subdomain)
                self.sl.n_unscanned += 1
        except Exception as e:
            self.log.fatal(('Inserting target %s.' % subdomain), False)
            print e


    def new_targets(self, new_domain):
        if not self.domain == new_domain.rstrip('.') and self.domain in new_domain:
            if not self.check_wildcard(new_domain):
                try:
                    self.mutex.acquire()
                    subdomain = new_domain.split('.')[0].rstrip('0123456789')
                    self.append_target(subdomain)  # this is here for adding new targets found from plugins
                    for d in reversed(range(0, 21)):
                        self.append_target('%s%02d' % (subdomain, d))
                        self.append_target('%s%d' % (subdomain, d))
                    for s in self.deep_domains:
                        self.append_target(s + '.' + subdomain)
                except Exception as e:
                    self.log.fatal(('Adding new target %s, %s' % (new_domain, subdomain)), False)
                    print (e)
                finally:
                    self.mutex.release()


    def parse_record(self, ans, query):
        wildcard = False
        try:
            for r in ans:
                if r.rdtype == 1:  # A RECORD
                    d = r.name.to_text().rstrip('.').decode('idna').encode('utf-8')
                    for x in r.items:
                        item = x.to_text()
                        if item in self.a_wildcard:
                            wildcard = True
                        else:
                            self.sl.items.append([d, item])
                            self.log.log_queue.append(self.f1.format(d +' ') + self.f2.format('A') + self.f3.format(item))
                            self.log.csv_queue.append("%s,A,%s" % (d, item))


                if r.rdtype == 5:  # CNAME RECORD
                    d = r.name.to_text().rstrip('.').decode('idna').encode('utf-8')
                    for x in r.items:
                        item = x.to_text()
                        if item in self.cname_wildcard:
                            wildcard = True
                        else:
                            self.sl.items.append([d, item])
                            self.log.log_queue.append(self.f1.format(d +' ') + self.f2.format('CNAME') + self.f3.format(item.rstrip('.')))
                            self.log.csv_queue.append("%s,CNAME,%s" % (d, item.rstrip('.')))

                if r.rdtype == 12:  # PTR RECORD
                    #d = r.name.to_text().rstrip('.').decode('utf-8').decode('idna')
                    for x in r.items:
                        item = x.to_text()
                        if self.domain.split('.')[-2] in item:
                            if not [y for y in self.sl.items if item.rstrip('.') in y if query in y[1]]:
                                self.sl.items.append([item, query])
                                self.log.log_queue.append(self.f1.format(item.rstrip('.') +' ') + self.f2.format('PTR') + self.f3.format(query))
                                self.log.csv_queue.append("%s,PTR,%s" % (item.rstrip('.'), query))
                            else:
                                wildcard = True

                if r.rdtype == 16:  # TXT RECORD
                    d = r.name.to_text().rstrip('.').decode('idna').encode('utf-8')
                    for x in r.items:
                        item = x.to_text()
                        if item in self.txt_wildcard:
                            wildcard = True
                        else:
                            if [t for t in self.config['config']['txt_record_search'] if t in item]:
                                self.sl.items.append([d, item])
                                self.log.log_queue.append(self.f1.format(d +' ') + self.f2.format('TXT') + self.f3.format(item))
                                self.log.csv_queue.append("%s,TXT,%s" % (d, item))

                if r.rdtype == 28:  # AAAA RECORD
                    d = r.name.to_text().rstrip('.').decode('idna').encode('utf-8')
                    for x in r.items:
                        item = x.to_text()
                        if item in self.aaaa_wildcard:
                            wildcard = True
                        else:
                            self.sl.items.append([d, item])
                            self.log.log_queue.append(self.f1.format(d +' ') + self.f2.format('AAAA') + self.f3.format(item))
                            self.log.csv_queue.append("%s,AAAA,%s" % (d, item))

                if r.rdtype == 15:  # MX RECORD
                    d = r.name.to_text().rstrip('.').decode('idna').encode('utf-8')
                    for x in r.items:
                        item = x.to_text()
                        if item in self.mx_wildcard:
                            wildcard = True
                        else:
                            self.sl.items.append([d, item])
                            self.log.log_queue.append(self.f1.format(d +' ') + self.f2.format('MX') + self.f3.format(item.split(' ')[1].rstrip('.')))
                            self.log.csv_queue.append("%s,MX,%s" % (d, item.split(' ')[1].rstrip('.')))
                            new = ['mail._domainkey', '_dmarc', 'default._domainkey', 'selector1._domainkey', 'selector2._domainkey']
                            for n in new:
                                if d == self.domain:
                                    self.append_target(n)
                                else:
                                    self.append_target(n + '.' + d.replace(self.domain, '').strip('.').decode('utf-8'))
        except Exception as e:
            self.log.fatal(('Parsing records for: %s with answer %s' % (query, ans)), False)
            print (e)
        return wildcard


    def scan_worker(self):
        while True:
            if self.handler.SIGINT:
                return
            self.mutex.acquire()
            try:
                if self.record is 'PTR':
                    tests = ['PTR']
                    subdomain = self.sl.ptr_unscanned_ip.pop(0)
                    self.sl.ptr_scanned += 1
                else:
                    subdomain = self.sl.unscanned.pop(0)
                    if self.args.record: tests = [self.record]
                    elif self.record is 'A':
                        if subdomain == '': tests = ['A', 'TXT', 'MX']
                        else: tests = ['A']
                    else: tests = ['ANY']
            except:
                if len(self.sl.unscanned) is 0:
                    return
            finally:
                self.mutex.release()
            time.sleep(self.throttle)
            # if domain already has been scanned (remove duplicates)
            # else, add domain to "scanned" list.
            if subdomain in self.sl.scanned:
                continue
            else:
                self.sl.scanned.append(subdomain)
            for t in tests:
                if self.record is 'PTR':
                    d = subdomain
                else:
                    d = (subdomain + u'.' + self.domain).lower().lstrip('.')
                try:
                    ans = lookup(d.encode('utf-8'), t, self.dns, self.protocol, self.timeout)
                    if ans:
                        wildcard = self.parse_record(ans, d)
                        if ans and not wildcard and d != self.domain and self.record is not 'PTR':
                            self.new_targets(d)
                            self.sl.found.append(d)
                    elif ans == False and self.record is not 'PTR':
                        hit = [x for x in self.sl.scan_failed if x[0] == subdomain]
                        if hit:
                            z = self.sl.scan_failed.index(hit[0])
                            self.sl.scan_failed[z][1] += 1
                            if hit[0][1] > self.retry:
                                self.sl.failcounter += 1
                                if self.args.verbose:
                                    self.log.status('Failed lookup on %s' % d + ' ' * 20, False)
                                self.log.error_queue.append('Failed lookup on %s' % d )
                                continue
                        else:
                            self.sl.scan_failed.append([subdomain, 1])
                        self.sl.scanned.remove(subdomain)
                        self.sl.unscanned.insert(0,subdomain)
                    if ans != False and self.record is not 'PTR' and ((t == 'ANY' or t == 'A') or t == self.args.record):
                        # basically don't count queries that's TXT or MX if querying a server doesn't respond to ANY
                        self.sl.n_scanned += 1
                        self.sl.n_unscanned -= 1
                except Exception as e:
                    try:
                        self.log.fatal(('Domain Query failed on %s.'  % d), False)
                    except:
                        pass
                    print (e)


    def subnets(self):
        # Parse through results and check for similar IP's and assign them to "subnets"
        # TODO: For god's sake, I'm hardly able to understand this myself.
        for z in self.sl.items:
            if re.search("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", z[1]):
                ip = ".".join([z[1].split('.')[i] for i in [0, 1, 2]]) + '.0-255'
                hit = [x for x in self.sl.subnets if x[0] == ip]
                if hit:
                    z = self.sl.subnets.index(hit[0])
                    self.sl.subnets[z][1] += 1
                else:
                    self.sl.subnets.append([ip, 1])
        self.sl.subnets.sort()


    def ptr_scan(self):
        while self.sl.subnets:
            subnet = self.sl.subnets.pop(0)
            subnet = subnet[0][:subnet[0].rfind('.') + 1]
            for i in range(0, 256):
                self.sl.ptr_unscanned_ip.append(subnet + str(i))
        n_ip = len(self.sl.ptr_unscanned_ip)
        if self.args.ptr and n_ip > 0:
            self.log.good('Checking PTR records for related subnets', False)
            self.record = 'PTR'
            threads = []
            for i in range(self.threads):
                t = Thread(target=self.scan_worker)
                threads.append(t)
                t.start()
            while any(t.is_alive() for t in threads):
                if sys.stdout.isatty() and not self.args.quiet:
                    self.log.printer()
                    percentage = math.ceil(self.sl.ptr_scanned + 0.0)/n_ip*100
                    sys.stdout.write("Status: " + col.cyan + "%d/%d " % (self.sl.ptr_scanned,  n_ip) + col.end + "IP's tested."
                                     + col.brown + " %.2f%%" % percentage + col.end + " done. \r")
                    sys.stdout.flush()
                time.sleep(0.05)
            # just to ensure everything is out
            self.log.printer()
            if not self.args.quiet: sys.stdout.write(' ' * 64 + '\n')


    def stats(self):
        if self.sl.ptr_scanned == 0:
            self.log.warn('No PTR records found for %s.' % self.domain, False)
        self.log.normal('\n\nA total of %d domains records was found.' % len(self.sl.items), True)
        self.subnets()
        if self.sl.subnets:
            self.log.normal('IP range detected:', True)
            for x in self.sl.subnets:
                self.log.normal('  %s - %d hits' % (x[0], x[1]), True)
        else:
            self.log.normal("No subnets was discovered.", True)
        if not self.args.quiet: print ("\nDONE")


    def close(self):
        del(self.log)

    def __exit__(self):
        self.close()

    def __del__(self):
        self.close()
