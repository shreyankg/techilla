# Copyright 2010, 2012 Red Hat Inc.
# Author: Shreyank Gupta <sgupta@redhat.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
# the full text of the license.

import base64
from datetime import datetime
import time

if hasattr(datetime, 'strptime'):
    #python 2.6
    strptime = datetime.strptime
else:
    #python 2.4 equivalent
    strptime = lambda date_string, format: datetime(*(time.strptime(date_string, format)[0:6]))


def attachment_encode(fh):
    """
    Ripped from python-bugzilla

    Return the contents of the file-like object fh in a form
    appropriate for attaching to a bug in bugzilla. This is the default
    encoding method, base64.
    """
    # Read data in chunks so we don't end up with two copies of the file
    # in RAM.
    chunksize = 3072 # base64 encoding wants input in multiples of 3
    data = ''
    chunk = fh.read(chunksize)
    while chunk:
        # we could use chunk.encode('base64') but that throws a newline
        # at the end of every output chunk, which increases the size of
        # the output.
        data = data + base64.b64encode(chunk)
        chunk = fh.read(chunksize)
    return data

def to_datetime(xmlrpc_time):
    """
    Converts a xmlrpclib.DateTime object to a datetime.datetime object
    """
    if not xmlrpc_time:
        return None
    if isinstance(xmlrpc_time, str):
        try:
            return strptime(xmlrpc_time, "%Y-%m-%d %H:%M:%S")
        except:
            return strptime(xmlrpc_time, "%Y.%m.%d %H:%M")
    else:
        return strptime(xmlrpc_time.value, "%Y%m%dT%H:%M:%S")

def extract(hash, *keys):
    """
    Extracts dictionary value in order of key appearance
    """
    for key in keys:
        if hash.has_key(key):
            return hash[key]

def show_bug_url(xmlprc_url):
    """
    Returns BZ show_bug.cgi url from xmlrpc.cgi url
    """
    return xmlprc_url.replace('xmlrpc.cgi', 'show_bug.cgi?id=') 
