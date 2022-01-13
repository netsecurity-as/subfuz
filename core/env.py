import os
import sys
from core.logger import Output, col

def setup_core_paths(subfuz):
    global DF_DIR
    global DF_FILE
    DF_FILE = os.path.realpath(subfuz)
    DF_DIR = os.path.dirname(subfuz)
    return (DF_FILE, DF_DIR)

class SIGINT_handler():
    def __init__(self):
        self.SIGINT = False

    def signal_handler(self, signal, frame):
        print (' ' * 60)
        Output().warn('CTRL+C pressed, aborting.', False)
        self.SIGINT = True

