#!/usr/bin/python 
 
import glob 
import os.path 

if os.path.exists('/etc/tequilla/tequilla.conf'):
    conffile = glob.glob(os.path.join('/etc/tequilla/tequilla.conf')) 
else:
    conffile = glob.glob(os.path.join('tequilla.conf')) 
for f in conffile:
    execfile(f)
