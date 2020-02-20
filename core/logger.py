import sys, os

"""
import logger
# define output files
l = logger.Output('test.txt', 'test.csv')
# log sample
l.good('test', True)
# append to printer queue and print
l.log_queue.append('test.com')
l.csv_queue.append('1.2.3.4,A,test.com')
l.printer()
# del / close object to close up the output files
del(l)
"""

class col:
    #TODO, move terminal check to env.py, also create a colour scheme for windows terminals
    if sys.stdout.isatty() and not os.name == 'nt':
        green = '\033[32m'
        blue = '\033[94m'
        red = '\033[31m'
        yellow = '\033[93m'
        brown = '\033[33m'
        cyan = '\033[96m'
        end = '\033[0m'
    else:
        green = ''
        blue = ''
        red = ''
        yellow = ''
        brown = ''
        cyan = ''
        end = ''

class Output():
    def __init__(self, log_filename=False, csv_filename=False, error_filename=False, quiet=False):
        self.log_queue = []
        self.csv_queue = []
        self.error_queue = []
        self.already_prined = []
        self.logfile = False
        self.csvfile = False
        self.errorfile = False
        self.quiet = quiet
        if log_filename:
            try:
                self.logfile = open(log_filename, "a+")
            except:
                self.fatal("Could not open output file: %s" % log_filename, False)
                sys.exit(1)
        if csv_filename:
            try:
                if csv_filename == "-":
                    self.csvfile = sys.stdout
                else:
                    self.csvfile = open(csv_filename, "a+")
            except:
                self.fatal("Could not open output file: %s" % csv_filename, False)
                sys.exit(1)
        if error_filename:
            try:
                    self.errorfile = open(error_filename, "a+")
            except:
                self.fatal("Could not open output file: %s" % error_filename, False)
                sys.exit(1)

    def printer(self):
        while self.log_queue:
            n_line = self.log_queue.pop(0)
            if n_line not in self.already_prined:
                self.already_prined.append(n_line)
                self.normal(n_line, True)
        while self.csv_queue:
            c_line = self.csv_queue.pop(0)
            if c_line not in self.already_prined:
                self.already_prined.append(c_line)
                self.csv(c_line)
        while self.error_queue:
            self.error(self.error_queue.pop(0))

    def csv(self, message):
        if self.csvfile:
            self.csvfile.write(message + '\n')

    def error(self, message):
        if self.errorfile:
            try:
                self.errorfile.write(message.encode('utf-8') + '\n')
            except:
                print('ERROR - unable to write to file: ' + message)

    def normal(self, message, log):
        if not self.quiet: print(message)
        if self.logfile and log:
            self.logfile.write(message + '\n')

    def status(self, message, log):
        if not self.quiet: print(col.blue + "[*] " + col.end + message)
        if self.logfile and log:
            self.logfile.write("[*] " + message + '\n')

    def good(self, message, log):
        if not self.quiet: print(col.green + "[+] " + col.end + message)
        if self.logfile and log:
            self.logfile.write("[+] " + message + '\n')

    def neutral(self, message, log):
        if not self.quiet: print(col.yellow + "[X] " + col.end + message)
        if self.logfile and log:
            self.logfile.write("[X] " + message + '\n')

    def warn(self, message, log):
        if not self.quiet: print(col.red + "[-] " + col.end + message)
        if self.logfile and log:
            self.logfile.write("[-] " + message + '\n')

    def fatal(self, message, log):
        if not self.quiet: print("\n" + col.red + "FATAL: " + message + col.end)
        if self.logfile and log:
            self.logfile.write("FATAL: " + message + '\n')

    def close(self):
        if self.csvfile: self.csvfile.close()
        if self.logfile: self.logfile.close()

    def __exit__(self):
        self.close()

    def __del__(self):
        self.close()


