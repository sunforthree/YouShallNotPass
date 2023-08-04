#!/bin/python3
import os
try:
    from scapy.all import *
except ModuleNotFoundError:
    # Scapy happens to be installed locally, but this script has to run as sudo...
    os.sys.path.append('/home/' + os.getlogin() + '/.local/lib/python3.8/site-packages')
    # print(os.sys.path)
    from scapy.all import *

# sendp("Hello World!", iface='ens3f0', loop=1, inter=1)
sendp("Hello World!", iface='ens3f1', loop=1, inter=1)