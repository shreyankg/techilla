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
import socket
import errno
import os


from classes import Bug, Component, User
from utils import extract, attachment_encode

BUGZILLA_URL = 'https://bugzilla.redhat.com/xmlrpc.cgi'
COOKIE_DIR = '/tmp/bzcookies/'


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
        user|username|login     : Bugzilla login, usually an email id.
        password|passwd           : Password for bugzilla
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
        if http_proxy:
            self.http_proxy = http_proxy
        if not self.http_proxy and os.environ.has_key('http_proxy'):
            self.http_proxy = os.environ['http_proxy']

        # Set up the transport
        self.initcookiefile() # sets _cookiejar
        if self.url.startswith('https'):
            self._transport = SafeCookieTransport()
        else:
            self._transport = CookieTransport() 
        self._transport.user_agent = self.user_agent
        self._transport.cookiejar = self._cookiejar
        
        # Set HTTP proxy if required
        if self.http_proxy:
            self._transport.set_proxy(self.http_proxy)

        # Assume ends with /xmlrpc.cgi
        if not self.url.endswith('xmlrpc.cgi'):
            self.url = urllib2.urlparse.urljoin(self.url, 'xmlrpc.cgi')

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
            contenttype: The mime-type of the attached file. Defaults to
                         application/octet-stream if not set. NOTE that text
                         files will *not* be viewable in bugzilla unless you 
                         remember to set this to text/plain. So remember that!
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
            kwargs['content_type'] = 'application/octet-stream'
        else:
            kwargs['content_type'] = kwargs['contenttype']
        if not kwargs['content_type'] == 'text/plain':
            kwargs['data'] = attachment_encode(f)
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
        cookie_p = urllib2.HTTPCookieProcessor(self._cookiejar)
        opener = urllib2.build_opener(cookie_p)
        return opener.open(url)
        

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


class CookieTransport(xmlrpclib.Transport):
    """
    A subclass of xmlrpclib.Transport that supports cookies.
    """
    cookiejar = None
    scheme = 'http'

    # Cribbed from xmlrpclib.Transport.send_user_agent 
    def send_cookies(self, connection, cookie_request):
        if self.cookiejar is None:
            self.cookiejar = cookielib.CookieJar()
        elif self.cookiejar:
            self.cookiejar.add_cookie_header(cookie_request)
            # Pull the cookie headers out of the request object...
            cookielist=list()
            for h,v in cookie_request.header_items():
                if h.startswith('Cookie'):
                    cookielist.append([h,v])
            # ...and put them over the connection
            for h,v in cookielist:
                connection.putheader(h,v)

    # This is the same request() method from xmlrpclib.Transport,
    # with a couple additions noted below

    def mod_request(self, host, handler, request_body, verbose=0):
        h = self.make_connection(host)
        if verbose:
            h.set_debuglevel(1)

        # ADDED: construct the URL and Request object for proper cookie handling
        request_url = "%s://%s%s" % (self.scheme,host,handler)
        cookie_request  = urllib2.Request(request_url) 

        self.send_request(h,handler,request_body)
        self.send_host(h,host) 
        self.send_cookies(h,cookie_request) # ADDED. creates cookiejar if None.
        self.send_user_agent(h)
        self.send_content(h,request_body)

        if hasattr(h, 'getreply'):
            # python 2.6 
            errcode, errmsg, headers = h.getreply()

            # ADDED: parse headers and get cookies here
            cookie_response = CookieResponse(headers)
            # Okay, extract the cookies from the headers
            self.cookiejar.extract_cookies(cookie_response,cookie_request)
            # And write back any changes
            if hasattr(self.cookiejar,'save'):
                try:
                    self.cookiejar.save(self.cookiejar.filename)
                except e:
                    print "Couldn't write cookiefile %s: %s" % \
                            (self.cookiejar.filename,str(e))

            if errcode != 200:
                raise xmlrpclib.ProtocolError(
                    "%s://%s%s" % (self.scheme,host,handler),
                    errcode, errmsg,
                    headers
                    )

            self.verbose = verbose

            try:
                sock = h._conn.sock
            except AttributeError:
                sock = None

            f = h.getfile()
            retval = self._parse_response(f, sock)
            return retval
        else:
            # python 2.7
            try:
                response = h.getresponse(buffering=True)

                # ADDED: parse headers and get cookies here
                cookie_response = CookieResponse(response.msg)
                # Okay, extract the cookies from the headers
                self.cookiejar.extract_cookies(cookie_response,cookie_request)
                # And write back any changes
                if hasattr(self.cookiejar,'save'):
                    try:
                        self.cookiejar.save(self.cookiejar.filename)
                    except Exception, e:
                        print "Couldn't write cookiefile %s: %s" % \
                                (self.cookiejar.filename,str(e))

                if response.status == 200:
                    self.verbose = verbose
                    return self.parse_response(response)
            except xmlrpclib.Fault:
                raise
            except Exception:
                # All unexpected errors leave connection in
                # a strange state, so we clear it.
                self.close()
                raise

        #discard any response data and raise exception
        if (response.getheader("content-length", 0)):
            response.read()
        raise xmlrpclib.ProtocolError(
            host + handler,
            response.status, response.reason,
            response.msg,
            )

    def request(self, host, handler, request_body, verbose=0):
        #retry request once if cached connection has gone cold
        for i in (0, 1):
            try:
                return self.mod_request(host, handler, request_body, verbose)
            except socket.error, e:
                if i or e.errno not in (errno.ECONNRESET, errno.ECONNABORTED):
                    raise
            except httplib.BadStatusLine: #close after we sent request
                if i:
                    raise

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


class SafeCookieTransport(xmlrpclib.SafeTransport, CookieTransport):
    """
    SafeTransport subclass that supports cookies.
    """
    scheme = 'https'
    request = CookieTransport.request


class BugzillaLoginException(Exception):
    """
    Bugzilla exception for login failure.
    """
    def __init__(self, msg=''):
        self.msg = msg

    def __str__(self):
        return  "Login failure. %s" % self.msg

