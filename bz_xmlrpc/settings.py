#!/usr/bin/python 
 
import glob 
import os.path 

if os.path.exists('/etc/ABIDiffWeb/settings.conf'):
    conffile = glob.glob(os.path.join('/etc/ABIDiffWeb/settings.conf')) 
else:
    conffile = glob.glob(os.path.join('bz_xmlrpc/settings.conf')) 
for f in conffile:
    execfile(f)
