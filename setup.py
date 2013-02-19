#!/usr/bin/env python
#
# Copyright 2011, 2013 Red Hat Inc.
# Author: Shreyank Gupta <sgupta@redhat.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.  See
# http://www.gnu.org/copyleft/gpl.html for the full text of the
# license.
#
"Techilla Bugzilla XMLRPC client"


from distutils.core import setup
from distutils.sysconfig import get_python_lib

doclines = __doc__.split("\n")

setup(
    name='techilla',
    version='4.4',
    description=doclines[0],
    long_description="\n".join(doclines[:]),
    platforms=["Linux"],
    author='Shreyank Gupta',
    author_email='sgupta@redhat.com',
    url='',
    license='http://www.gnu.org/licenses/old-licenses/gpl-2.0.html',
    packages=['bz_xmlrpc'],
)
