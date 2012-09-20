#!/usr/bin/python 
 
import glob 
import os.path 

if os.path.exists('/etc/techilla/techilla.conf'):
    conffile = glob.glob(os.path.join('/etc/techilla/techilla.conf')) 
else:
    conffile = glob.glob(os.path.join('techilla.conf')) 
for f in conffile:
    execfile(f)
