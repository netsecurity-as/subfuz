#!/usr/bin/python
# -*- coding: utf-8 -*-
import importlib, os, argparse, json, sys, io
from core import env
from core.domainfuzzer import SubFuz

banner = '''             ___     _____             
   ________ _\_ |___/ ____\_ __________
  /  ___/  |  \ __ \   __\  |  \___   /
  \___ \|  |  / \_\ \  | |  |  //    / 
 /____  >____/|___  /__| |____//_____ \\
      \/          \/                 \/\n
'''

VERSION = "2.0.7"

(SF_FILE, SF_DIR) = env.setup_core_paths(os.path.realpath(__file__))
PLUGINS_DIR     = os.path.join(SF_DIR, "plugins")
CORE_DIR        = os.path.join(SF_DIR, "core")


def initialize():
    with open('config.json') as json_data_file:
        config = json.load(json_data_file)

    override = config['config']['dns_override']
    protocol = config['config']['dns_override_protocol']
    record = config['config']['dns_override_record']
    timeout = config['config']['timeout']
    threads = config['config']['threads']
    throttle = config['config']['throttle']
    retry = config['config']['retry']

    PLUGINS = []
    _PLUGINS = []
    # TODO: find a more elegant way to load plugin names with unique names rather than "plugin.py"
    for path, dir, file in os.walk(PLUGINS_DIR):
        for d in dir:
            PLUGINS.append('plugins.' + d + '.plugin')
    for plugin in PLUGINS:
        try:
            _PLUGINS.append(importlib.import_module(plugin))
        except OSError:
            print ('Failed to load plugin %s', plugin)



    example_text = '''
Example usage:
  python subfuz.py -d example.com -w domain_dictionary.txt -all

SubFuz %s
Author: Torstein Mauseth @ Netsecurity
''' % VERSION
    parser = argparse.ArgumentParser(epilog=example_text, formatter_class=argparse.RawTextHelpFormatter)
    parser._action_groups.pop()
    required_args = parser.add_argument_group('required arguments')
    optional_args = parser.add_argument_group('optional arguments')
    plugin_args   = parser.add_argument_group('plugins')


    required_args.add_argument('-d', help='Specify domain to fuzz, or..', dest='target')
    required_args.add_argument('-l', help='Specify list of domains to fuzz', dest='target_list')
    optional_args.add_argument('-w', help='Specify fuzzing dictionary to use', dest='dictionary')
    optional_args.add_argument('-o', help='Write output to a file', dest='log_filename', required=False, default=False)
    optional_args.add_argument('-csv', help='Write output to a csv file. Use - for stdout', dest='csv_filename', required=False, default=False)
    optional_args.add_argument('-deep', help='Specify fuzzing dictionary for deep subdomain testing', required=False, default=False)
    optional_args.add_argument('-dns', default=None, help='{:32}'.format('Override DNS server to query')+ '{:5}'.format('[ %s ]' % override))
    optional_args.add_argument('-protocol', default=protocol, help='{:32}'.format('Override DNS protocol') + '{:5}'.format('[ %s ]' % protocol))
    optional_args.add_argument('-record', default=record, help='{:32}'.format('Override DNS query record') + '{:5}'.format('[ %s ]' % protocol))
    optional_args.add_argument('-p', type=int, default=timeout, help='{:32}'.format('DNS timeout') + '{:5}'.format('[ %d ] sec'% timeout))
    optional_args.add_argument('-z', type=int, default=throttle, help='{:32}'.format('DNS request throttle') + '{:5}'.format('[ %d ] ms' % throttle))
    optional_args.add_argument('-r', type=int, default=retry, help='{:32}'.format('DNS retries if failed') + '{:5}'.format('[ %d ]' % retry))
    optional_args.add_argument('-t', type=int, default=threads, help='{:32}'.format('Threads active') + '{:5}'.format('[ %d ]' % threads))
    optional_args.add_argument('-zone', action='store_false',  help="Disable Zone Transfer testing")
    optional_args.add_argument('-ptr', action='store_false',  help="Disable PTR check on related domains on the current /24 network")
    optional_args.add_argument('-quiet', action='store_true', help="Suppress terminal output")

    # Load plugins as optional arguments
    plugin_args.add_argument('-all', action='store_true', help='Enable all plugins')
    for plugin in _PLUGINS:
        try:
            if config['plugins'][plugin.NAME]['enable'] is True:
                plugin_args.add_argument('-' + plugin.NAME, action='store_true',  help=plugin.ARG_HELP)
        except:
            pass

    args = parser.parse_args()
    # verify that one of the required arguments has been set.
    if not bool(args.target) ^ bool(args.target_list):
        parser.print_help()
        sys.exit()
    if args.quiet and not bool(args.csv_filename) ^ bool(args.log_filename):
        print('Quiet mode must be used with either -o <logfile> and/or -csv <csvfile>')
        sys.exit()

    return (config, args, _PLUGINS)



if __name__ == "__main__":
    config, args, plugins = initialize()
    if not args.quiet: print (banner)
    if args.target_list:
        try:
            targets =  map(unicode.strip, io.open(args.target_list, encoding='utf-8', mode='r').readlines())
        except:
            print ("Could not open output file: %s" % args.target_list)
            sys.exit()
    elif args.target:
        targets = [args.target]
    for domain in targets:
        if not args.quiet: 
            print ("Scanning: %s" % domain)
        sf = SubFuz(domain, config, args, PLUGINS_DIR, CORE_DIR)
        sf.dns_server()
        sf.check_wildcard(sf.domain)
        sf.execute_plugins(plugins, sf)
        sf.scan()
        sf.subnets()
        sf.ptr_scan()
        sf.stats()
        del(sf)