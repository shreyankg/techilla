# Copyright 2010, 2013 Red Hat Inc.
# Author: Shreyank Gupta <sgupta@redhat.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
# the full text of the license.

import xmlrpclib
import cookielib
import urllib2
import httplib
import os
import mimetypes
import pycurl
import StringIO

from classes import Bug, Component, User
from utils import extract, _check_http_error

BUGZILLA_URL = 'https://bugzilla.redhat.com/xmlrpc.cgi'
COOKIE_DIR = os.path.expanduser('~/.techilla/')


USER_AGENT = 'Python-urllib2/%s ' % urllib2.__version__

class BugzillaBase:
    """
    Base class
    Handles authentication, cookies and proxy.
    """

    def __init__(self,**kwargs):
        """
        Initialize a Bugzilla instance.
        
        Optional Arguments:
        -------------------
        url                     : The Bugzilla URL. 
                May or maynot end with /xmlrpc.cgi.
                If does not end with /xmlrpc.cgi, it will be assumed.
                If not provided, value of BUGZILLA_URL will be defaulted to.
        
        cookie_jar|cookiejar    : cookielib.CookieJar/MozillaCookieJar object.
        ssl_verify|sslverify    : boolean value, whether to verify ssl
                                    certificate or not.
        user|username|login     : Bugzilla login, usually an email id.
        password|passwd         : Password for bugzilla
        http_proxy|proxy        : String specifying the HTTP proxy of the
        bypass                  : boolean value, asks client to bypass 
                                    password auth and use cookies if present
                client's connection.
                Usually of the form server:port or http://server:port

        """
        # Initialize public attributes for unlogged unstance
        self.user_agent = USER_AGENT
        self.logged_in = False
        self.user_id = None

        self._init_private_data()
        # Extract provided values or default
        self._cookiejar = extract(kwargs, 'cookie_jar', 'cookiejar')
        self._sslverify = extract(kwargs, 'ssl_verify', 'sslverify') or True
            
        self.url = extract(kwargs, 'url') or BUGZILLA_URL

        self.user = extract(kwargs, 'user', 'username', 'login') or ''
        self.password = extract(kwargs, 'password', 'passwd') or ''

        self.http_proxy = extract(kwargs, 'http_proxy', 'proxy') or ''
        self.bypass = extract(kwargs, 'bypass') or ''

        cookie_dir = extract(kwargs, 'cookie_dir') or COOKIE_DIR
        if not os.path.exists(cookie_dir):
            os.mkdir(cookie_dir)
        self.cookiefile = os.path.join(cookie_dir, '%s.cookie' % self.user)

        self.connect()

    def _init_private_data(self):
        """
        Initialize private variables used by this bugzilla instance.
        """
        self._cookiejar = None
        self._proxy = None
        self._transport = None

    #Methods for establishing bugzilla connection and logging in

    def initcookiefile(self, cookiefile=None):
        """
        Read the given (Mozilla-style) cookie file and fill in the
        cookiejar, allowing us to use saved credentials to access Bugzilla.
        If no file is given, self.cookiefile will be used.
        """
        if cookiefile: 
            self.cookiefile = cookiefile
        cj = cookielib.MozillaCookieJar(self.cookiefile)
        if os.path.exists(self.cookiefile):
            cj.load()
        else:
            # Create an empty cookiefile that's only readable by this user
            old_umask = os.umask(0077)
            cj.save(self.cookiefile)
            os.umask(old_umask)
        self._cookiejar = cj
        self._cookiejar.filename = self.cookiefile

    def connect(self, url='', http_proxy=''):
        """
        Connect to the bugzilla instance with the given url.
        
        If 'user' and 'password' are both set, we'll run login(). Otherwise
        you'll have to login() yourself before some methods will work.
        """
        if url:
            self.url = url
        # Assume ends with /xmlrpc.cgi
        if not self.url.endswith('xmlrpc.cgi'):
            self.url = urllib2.urlparse.urljoin(self.url, 'xmlrpc.cgi')

        if http_proxy:
            self.http_proxy = http_proxy
        if not self.http_proxy and os.environ.has_key('http_proxy'):
            self.http_proxy = os.environ['http_proxy']

        self.initcookiefile() 

        # Set up the transport
        self._transport = _CURLTransport(
            self.url, 
            self._cookiejar,
            sslverify=self._sslverify
            )

        self._transport.user_agent = self.user_agent
        
        # Set HTTP proxy if required
        if self.http_proxy:
            self._transport.set_proxy(self.http_proxy)

        # Set up the proxy, using the transport
        self._proxy = xmlrpclib.ServerProxy(self.url,self._transport,
            allow_none=True)
        # If cookies exist and password not provided, fake a login 
        if self._cookiejar._cookies and self.bypass:
            self._fake_login()
        elif self.user and self.password:
            self._logout()
            self.login()

    def disconnect(self):
        """
        Disconnect from the given bugzilla instance.
        """
        self._init_private_data() # clears all the connection state

    def _login(self,user,password):
        """
        Logs in using User.login
        """
        id = self._proxy.User.login({
            'login': user, 
            'password': password,
            })
        self.user_id = id['id']
        return self.user_id

    def _fake_login(self):
        """
        Fakes a login
        """
        self.logged_in = True
        self.password = ''

    def login(self,user=None,password=None):
        """
        Attempt to log in using the given username and password. Subsequent
        method calls will use this username and password. Returns False if 
        login fails, otherwise returns a numeric userid. It also sets the 
        logged_in attribute to True, if successful.

        If user is not set, the value of Bugzilla.user will be used. If *that*
        is not set, ValueError will be raised. 

        This method will be called implicitly at the end of connect() if user
        and password are both set. So under most circumstances you won't need
        to call this yourself.
        """
        if user:
            self.user = user
        if password:
            self.password = password

        if not self.user:
            raise ValueError, "missing username"
        if not self.password:
            raise ValueError, "missing password"
           
        try: 
            r = self._login(self.user,self.password)
            self.logged_in = True
            self.password = ''
        except xmlrpclib.Fault, f:
            r = False
        return r

    def _logout(self):
        """
        Clears cookies
        """
        self._cookiejar.clear()
        self._cookiejar.save()

    def logout(self):
        """
        Log out of bugzilla. Drops server connection and user info, and
        destroys authentication cookies.
        """
        self._logout()
        self.user = ''
        self.password = ''
        self.user_id  = None
        self.logged_in  = False

    
    # XMLRPC fetch methods

    def get_bugs(self, ids, comments, attachments):
        """
        Accepts a list of int/str bug ids 
        Fetches a group of bugs and returns a list of Bug objects
        """
        extra_fields = ['flags', 'description']
        if comments:
            extra_fields.append('comments')
        if attachments:
            extra_fields.append('attachments')
        ids = {'ids' : [str(id) for id in ids], 
            'extra_fields': extra_fields}

        out = self._proxy.Bug.get(ids)
        return [Bug(bug, self) for bug in out['bugs']]


    def get_bug_upstream(self, id, comments=False, attachments=False):
        """
        Used upstream Bug.get to fetch bug details. It's faily limited in
        funtionality, and makes extra calls to fetch comments and attachments.
        Also does not fetch keywords and many such attributes. 

        Use get_bug until Bug.get is upto the mark. 
        """
        bugs = self.get_bugs([id])
        bug = bugs[0]
        if comments:
            bug.get_comments()
        if attachments:
            bug.get_attachments()
        return bug

    def get_bug(self, id, comments=False, attachments=False):
        """
        Uses Bug.get to fetch bug with keywords, 
        attachments and comments
        """
        return self.get_bugs([id], comments, attachments)[0]

    def create(self, **kwargs):
        """
        Creates a new bug from the given parameters

        Compulsory parameters:
        ----------------------
        product                         (string)
        component                       (string)
        summary                         (string)
        version                         (string)
        
        Defaulted parameters:
        ---------------------
        description                     (string)
        op_sys                          (string)
        platform                        (string)
        priority                        (string)
        severity                        (string)
        
        Optional parameters:
        --------------------
        url                             (string)
        whiteboard                      (string)
        assigned_to                     (string)
        qa_contact                      (string)
        target_milestone                (string)
        keywords                        (comma separated string/array)

        """
        if kwargs.has_key('keywords'):
            if isinstance(kwargs['keywords'], list):
                kwargs['keywords'] = ', '.join(kwargs['keywords'])
        out = self._proxy.Bug.create(kwargs)
        kwargs['id'] = out['id']
        kwargs['status'] = 'NEW'
        return Bug(kwargs, self)

    def update_bugs(self, ids, **kwargs):
        """
        Update multiple bugs with given parameters

        Accepted parameters:
        --------------------
        product                         (string)
            (also update component, version and target_milestone)
        component                       (string)
            (assigned_to, qa_contact gets updated)
        version                         (string)
        target_milestone                (string)
        op_sys                          (string)
        platform                        (string)
        summary                         (string)
        priority                        (string)
        severity                        (string)
        url                             (string)
        whiteboard                      (string)
        comment                         (string)
                commentprivacy          (boolean) 
        assigned_to                     (string)
        qa_contact                      (string)
        dupe_id                         (integer)
        status                          (string)
                resolution              (string)
        fixed_in                        (string)
        [add|remove]_groups              (array)
        [add|delete]_dependson          (array)
        [add|delete]_blocked            (array)
        [add|remove|set]_keywords (array)
        [add|delete]_partner            (array)
        [add|delete]_verified           (array)
        [add|delete]_cc                 (array)
        [add|delete]_alias              (array)
        [devel|qa|internal]_whiteboard  (string)
        [cclist|reporter]_accessible    (boolean)

        eg: 
        bz.update_bugs(
            [123456, 234567],
            product='Red Hat Enterprise Linux 6', 
            component='gimp',
            version='6.0', 
            target_milestone='rc', 
            add_group=['redhat']
            ) 

        """
        return self._update(ids, kwargs)

    def _update(self, ids, kwargs):
        """
        Private method to update bugs
        """
        # Hack to allow BZ attribute name changes to remain unaffected.
        pairs = [
            ('status', 'bug_status'),
            ('summary', 'short_desc'),
            ('platform', 'rep_platform'),
            ('severity', 'bug_severity'),
            ('whiteboard', 'status_whiteboard'),
            ]
        for p1, p2 in pairs:
            if p1 in kwargs:
                kwargs[p2] = kwargs[p1]
            if p2 in kwargs:
                kwargs[p1] = kwargs[p2]

        # Get default assignee and qa contact on component change
        if 'component' in kwargs:
            kwargs['reset_assigned_to'] = True
            kwargs['reset_qa_contact'] = True
        kwargs['ids'] = ids
        
        # Fix comments
        if 'comment' in kwargs:
            kwargs['comment'] = {'body': kwargs['comment']}
        if 'commentprivacy' in kwargs:
            kwargs['comment']['is_private'] = kwargs['commentprivacy']
            kwargs.pop('commentprivacy')
        
        # Fix keywords
        keywords = {}
        for each in ['add_keywords', 'delete_keywords', 'set_keywords']:
            if each in kwargs:
                keywords[each.split('_')[0]] = kwargs[each]
                kwargs.pop(each)
        if keywords:
            kwargs['keywords'] = keywords

        # Fix groups
        groups = {}
        for each in ['add_groups', 'delete_groups']:
            if each in kwargs:
                groups[each.split('_')[0]] = kwargs[each]
                kwargs.pop(each)
        if groups:
            kwargs['groups'] = groups 
        out =  self._proxy.Bug.update(kwargs)
        return out['bugs']

    def search(self, **kwargs):
        """
        Search Bugzilla, with complete bug attributes

        Accepted parameters:
        --------------------
        id                                          (integer)
        alias                                       (string)
        assigned_to                                 (string)
        qa_contact                                  (string)
        reporter                                    (string)
        summary                                     (string)
        product                                     (string)
        component                                   (string)
        version                                     (string)
        target_milestone                            (string)
        op_sys                                      (string)
        platform                                    (string)
        priority                                    (string)
        severity                                    (string)
        url                                         (string)
        whiteboard                                  (string)
        status                                      (string)
        resolution                                  (string)
        fixed_in                                    (string)

        limit - limit to <limit> bugs               (integer)
            offset - starting position for <limit>  (integer)
                                            
        """
        kwargs['exclude_fields'] = ['internals']
        kwargs['extra_fields'] = ['description']
        out = self._proxy.Bug.search(kwargs)
        return [Bug(bug, self) for bug in out['bugs']]

    def component(self, product_name, component_name):
        """
        Fetch component given product and component name
        Returns component object
        """
        hash = self._proxy.Component.get({
            'names': {
                'product': product_name,
                'component': component_name, 
                }
            })
        return Component(hash['components'][0])

    def get_components(self, product_id):
        """
        Fetch components for a given product id.
        """
        return self._get_components_multiple([product_id]).values()[0][0]

    def _get_components_multiple(self, ids):
        """
        Fetch details about multiple products given product id
        """
        return self._proxy.Product.get({'ids': ids})

    def _get_comments(self, ids):
        """
        Fetches comments for multiple bug ids
        """
        #TODO implement new_since
        ids = [str(id) for id in ids]
        out = self._proxy.Bug.comments({
            'ids': ids
            })
        return out['bugs']

    def _get_attachments(self, ids):
        """
        Fetches attachment info for multiple bug ids
        """
        ids = [str(id) for id in ids]
        out = self._proxy.Bug.attachments({
            'ids': ids
            })
        return out['bugs']

    def _get_flags(self, ids):
        """
        Fetches flags for multiple bug ids
        """
        out = self._proxy.Flag.get({
            'ids': ids
            })
        return out['bugs']

    def update_flags(self, ids, hash, nomail=False):
        """
        Updates flags for given bug ids
        hash is a dictionary with flagname as key and state as value 
        e.g. {
            'flag1': '+',
            'flag2': '?',
            }
        """
        updates = [{'name': name, 'status': status} for name, status in
            hash.iteritems()]
        out = self._proxy.Flag.update({
            'ids': ids,
            'nomail': nomail,
            'updates': updates,
            })
        return True

    def get_users(self, logins):
        """
        Fetches user details for multiple users
        Accepts a array of login emails
        """
        out = self._proxy.User.get({
            'names': logins
        })
        return [User(user) for user in out['users']]

    def get_user(self, login):
        """
        Fetches details for single user
        """
        users = self.get_users([login])
        return users[0]

    def create_user(self, login, name=None, password=None):
        """
        Create a user
        User trying this should have 'editusers' privilege.
        """
        in_hash = {
            'email': login
            }
        if name:
            in_hash['full_name'] = name
        if password:
            in_hash['password'] = password
        out = self._proxy.User.create(in_hash)
        return out['id']

    def update_users(self, logins, **kwargs):
        """
        Update single/multiple user(s). 
        User calling this method should have 'editusers' privilege.

        Pass string for logins if you wanna update a single user otherwise
        pass array of logins.

        Parameters:
        -----------
        logins - Single or array for login names            (string|array)
        name                                                (string)
        password                                            (string)
        [add|remove]_group - list of group names            (array of strings)

        e.g. update_users(
            'abc@xyz.com', 
            name='New Name',
            password='newpasswd',
            add_group=['g1', 'g2'],
            remove_group=['g3', 'g4']
            )
        """
        #name is changed to real_name
        if 'name' in kwargs:
            kwargs['real_name'] = kwargs['name']
            del kwargs['name']

        out = self._proxy.User.update({
            'names': logins,
            'updates': kwargs
            })
        return out['users_updates']

    def add_attachment(self, id, file, description, **kwargs):
        """
        Attach a file the bug ID. Returns the ID of the attachment
        or returns None if something goes wrong.
        file should be a filename.
        description is the short description of this attachment.
        Optional keyword args are as follows:
            filename:  this will be used as the filename for the attachment.
                       REQUIRED if attachfile is a file-like object with no
                       'name' attribute, otherwise the filename or .name
                       attribute will be used.
            comment:   An optional comment about this attachment.
            isprivate: Set to True if the attachment should be marked private.
            ispatch:   Set to True if the attachment is a patch.
            contenttype: The mime-type of the attached file. Will try to guess
                         mimetype if not set. NOTE that text files will *not*
                         be viewable in bugzilla unless you remember to set
                         this to text/plain. So remember that!  
        """
        f = open(file)
        kwargs['ids'] = id
        kwargs['summary'] = description
        if 'filename' not in kwargs:
            kwargs['file_name'] = os.path.basename(f.name)
        else:
            kwargs['file_name'] = kwargs['filename']
        if 'isprivate' not in kwargs:
            kwargs['is_private'] = False
        else:
            kwargs['is_private'] = kwargs['isprivate']
        if 'contenttype' not in kwargs:
            ctype = mimetypes.guess_type(file)[0]
            if ctype:
                kwargs['content_type'] = ctype
            else:
                kwargs['content_type'] = 'application/octet-stream'
        else:
            kwargs['content_type'] = kwargs['contenttype']
        if not kwargs['content_type'] == 'text/plain':
            kwargs['data'] = xmlrpclib.Binary(f.read())
        else:
            kwargs['data'] = f.read()
        out = self._proxy.Bug.add_attachment(kwargs)
        return out


    def add_comment(self, bug_id, comment, private=False):
        """
        Add a comment to a given bug id
        pass private=True for private comment
        """
        hash = {
            'id': bug_id,
            'comment': comment,
            }
        if private:
            hash['private'] = True
        out = self._proxy.Bug.add_comment(hash)
        if out:
            return out['id']
        else:
            return False


    def _fetch_url(self, url):
        """
        Fetches a url in BZ using cookies
        """
        headers = {}
        ret = StringIO.StringIO()

        def headers_cb(buf):
            if not ":" in buf:
                return
            name, val = buf.split(":", 1)
            headers[name.lower()] = val

        c = self._transport.c
        c.setopt(pycurl.URL, url)
        c.setopt(pycurl.WRITEFUNCTION, ret.write)
        c.setopt(pycurl.HEADERFUNCTION, headers_cb)
        c.setopt(pycurl.FOLLOWLOCATION, 1)
        c.perform()
        c.close()

        # Hooray, now we have a file-like object with .read() 
        ret.seek(0)
        return ret
        

class CookieResponse:
    """
    Fake HTTPResponse object that we can fill with headers we got elsewhere.
    We can then pass it to CookieJar.extract_cookies() to make it pull out the
    cookies from the set of headers we have.
    """
    
    def __init__(self,headers): 
        self.headers = headers
    
    def info(self): 
        return self.headers

class _CURLTransport(xmlrpclib.Transport):
    """
    Pycurl's implementation of xmlrpclib.Transport
    Useful for getting ssl certificates verified.
    """

    def __init__(self, url, cookiejar,
                 sslverify=True, sslcafile=None, debug=0):

        if hasattr(xmlrpclib.Transport, "__init__"):
            xmlrpclib.Transport.__init__(self, use_datetime=False)

        self.verbose = debug

        # transport constructor needs full url too, as xmlrpc does not pass
        # scheme to request
        self.scheme = urllib2.urlparse.urlparse(url)[0]
        if self.scheme not in ["http", "https"]:
            raise Exception("Invalid URL scheme: %s (%s)" % (self.scheme, url))

        self.c = pycurl.Curl()
        self.c.setopt(pycurl.POST, 1)
        self.c.setopt(pycurl.CONNECTTIMEOUT, 30)
        self.c.setopt(pycurl.HTTPHEADER, [
            "Content-Type: text/xml",
        ])
        self.c.setopt(pycurl.VERBOSE, debug)

        self.set_cookiejar(cookiejar)

        # ssl settings
        if self.scheme == "https":
            # override curl built-in ca file setting
            if sslcafile is not None:
                self.c.setopt(pycurl.CAINFO, sslcafile)

            # disable ssl verification
            if not sslverify:
                self.c.setopt(pycurl.SSL_VERIFYPEER, 0)
                self.c.setopt(pycurl.SSL_VERIFYHOST, 0)

    def set_cookiejar(self, cj):
        self.c.setopt(pycurl.COOKIEFILE, cj.filename or "")
        self.c.setopt(pycurl.COOKIEJAR, cj.filename or "")

    def get_cookies(self):
        return self.c.getinfo(pycurl.INFO_COOKIELIST)

    def _open_helper(self, url, request_body):
        self.c.setopt(pycurl.URL, url)
        self.c.setopt(pycurl.POSTFIELDS, request_body)

        b = StringIO.StringIO()
        headers = StringIO.StringIO()
        self.c.setopt(pycurl.WRITEFUNCTION, b.write)
        self.c.setopt(pycurl.HEADERFUNCTION, headers.write)

        try:
            m = pycurl.CurlMulti()
            m.add_handle(self.c)
            while True:
                if m.perform()[0] == -1:
                    continue
                num, ok, err = m.info_read()
                ignore = num

                if ok:
                    m.remove_handle(self.c)
                    break
                if err:
                    m.remove_handle(self.c)
                    raise pycurl.error(*err[0][1:])
                if m.select(.1) == -1:
                    # Looks like -1 is passed straight up from select(2)
                    # While it's not true that this will always be caused
                    # by SIGINT, it should be the only case we hit
                    log.debug("pycurl select failed, this likely came from "
                              "SIGINT, raising")
                    m.remove_handle(self.c)
                    raise KeyboardInterrupt
        except pycurl.error, e:
            raise xmlrpclib.ProtocolError(url, e[0], e[1], None)

        b.seek(0)
        headers.seek(0)
        return b, headers

    def request(self, host, handler, request_body, verbose=0):
        self.verbose = verbose
        url = "%s://%s%s" % (self.scheme, host, handler)

        # xmlrpclib fails to escape \r
        request_body = request_body.replace('\r', '&#xd;')

        body, headers = self._open_helper(url, request_body)
        _check_http_error(url, body.getvalue(), headers.getvalue())

        return self.parse_response(body)

    # To enable proxy
    def set_proxy(self, http_proxy):
        self.http_proxy = http_proxy
        self.make_connection = self._make_proxy_connection
        self.send_request = self._send_proxy_request
        self.send_host = self._send_proxy_host
    
    def _make_proxy_connection(self, host):
        self.realhost = host
        h = httplib.HTTP(self.http_proxy)
        return h
        
    def _send_proxy_request(self, connection, handler, request_body):
        url = '%s://%s%s' % (self.scheme, self.realhost, handler)
        connection.putrequest("POST", url)

    def _send_proxy_host(self, connection, host):
        connection.putheader('Host', self.realhost)


class BugzillaLoginException(Exception):
    """
    Bugzilla exception for login failure.
    """
    def __init__(self, msg=''):
        self.msg = msg

    def __str__(self):
        return  "Login failure. %s" % self.msg

