# Copyright 2010, 2012, 2013 Red Hat Inc.
# Author: Shreyank Gupta <sgupta@redhat.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
# the full text of the license.

from datetime import datetime
import os
from utils import extract, to_datetime, show_bug_url

class Bug:
    """
    The Bugzilla Bug Class 
    """

    bz = None               #: :class:`bz_xmlrpc.base.BugzillaBase` instance

    id = 0                  #: Bug id
    summary = ''            #: Summary
    description = ''        #: Description
    assigned_to = ''        #: Assignee
    qa_contact = ''         #: QA Contact 
    reporter = ''           #: Reported by
    product = ''            #: Product
    component = ''          #: Component
    creation_time = ''      #: Created timestamp
    last_change_time = ''   #: Last Modified on
    dupe_of = 0             #: Duplicate of bug  
    priority = ''           #: Priority
    severity = ''           #: Severity
    partner = ''            #: Partner
    target_milestone = ''   #: Target Milestone
    status = ''             #: Status
    whiteboard = ''         #: Whiteboard
    resolution = ''         #: Resolution
    version = 0             #: Version
    platform = ''           #: Platform
    keywords = []           #: Keywords
    fixed_in = ''           #: Fixed in version

    #: List of :class:`~bz_xmlrpc.classes.Comment` objects
    comments = [] 

    #: List of :class:`~bz_xmlrpc.classes.Attachment` objects
    attachments = []
    
    #: List of :class:`_Group` objects. 
    #: Use :meth:`~bz_xmlrpc.classes.Bug.get_groups()` instead.
    groups = []             

    #: List of :class:`Flag` objects
    #: Use :meth:`~bz_xmlrpc.classes.Bug.get_flags()` instead
    flags = []              
        

    def __init__(self, hash, bz):
        """
        Initialise a bug object.

        :arg hash: Dictionary of bug details
        :arg bz: Instance of :class:`~bz_xmlrpc.base.BugzillaBase` object

        :return: Instance of :class:`Bug`
        .. note::
            No need to use this directly. 
            Use :meth:`~bz_xmlrpc.base.BugzillaBase.get_bug()`
            or :meth:`~bz_xmlrpc.base.BugzillaBase.search()`

        """

        self.bz = bz

        # Extract available data 
        if hash:
            self._populate(hash)

    def _be(self, *keys):
        """
        Private conviniance wrapper around extract. 
        Hash defaults to self._hash
        """
        return extract(self._hash, *keys)
        
    def _populate(self, hash):
        """
        Accepts a bug hash populates bug attributes
        """
        # Hack for searched bugs
        if 'internals' in hash:
            hash = hash['internals']
            hash['status'] = hash['status']['value']

        self._hash = hash

        self.id = self._be('id', 'bug_id') or self.id
        self.summary = self._be('summary', 'short_desc') or self.summary
        self.description = self._be('description') or self.description
        self.assigned_to = self._be('assigned_to') or self.assigned_to
        self.qa_contact = self._be('qa_contact') or self.qa_contact
        self.reporter = self._be('reporter', 'creator') or self.reporter
        self.product = self._be('product') or self.product
        self.component = self._be('component') or self.component
        self.creation_time = (to_datetime(self._be('creation_time'))
            or self.creation_time)
        self.last_change_time = (to_datetime(self._be('last_change_time')) 
            or self.last_change_time)

        self.dupe_of = self._be('dupe_of', 'dupe_id') or self.dupe_of
        self.priority = self._be('priority')  or self.priority
        self.severity = self._be('severity','bug_severity') or self.severity
        self.partner = self._be('cf_partner') or self.partner
        self.target_milestone = (self._be('target_milestone') or
            self.target_milestone)
        self.status = self._be('status', 'bug_status') or self.status
        self.whiteboard = (self._be('status_whiteboard', 'whiteboard')
            or self.whiteboard)
        self.resolution = self._be('resolution') or self.resolution
        self.version = self._be('version') or self.version
        self.platform = self._be('platform', 'rep_platform') or self.platform
        self.keywords = self._be('keywords') or self.keywords
        if isinstance(self.keywords, str):
            self.keywords = self.keywords.split(', ')
        self.fixed_in = self._be('fixed_in') or self.fixed_in

        self._comments = self._be('longdescs', 'comments')
        if self._comments:
            self._hash2comments(self._comments)

        self._attachments = self._be('attachments')
        if self._attachments:
             self._hash2attachments(self._attachments)

        self._groups = self._be('groups')
        if self._groups:
            self.groups = [_Group(group) for group in self._groups]

        self._flags = self._be('flags')
        if self._flags:
            self.flags = [Flag(flag) for flag in self._flags]

        if self.id and self.bz:
            self.url = show_bug_url(self.bz.url) + str(self.id)

    def _hash2comments(self, hash):
        self.comments = [Comment(self, each) for each in hash]
        if not self.description:
            self.description = self.comments[0].text

    def _hash2attachments(self, hash):
        self.attachments = [Attachment(self, each) for each in hash]

    def get_comments(self):
        """
        Fetches comments from Bugzilla, stores and returns them.

        For retriving comments without fetching them try the comments
        attribute 

        :rtype: list of :class:`~bz_xmlrpc.classes.Comment` objects
        """
        comment_list = \
            self.bz._get_comments([self.id])[str(self.id)]['comments']
        self._hash2comments(comment_list)
        return self.comments

    def get_attachments(self):
        """
        Fetches attachment info for the bug from the bugzilla, stores and 
        returns them.

        For retriving attachments without fetching them try the attachments
        attribute 

        :rtype: list of :class:`~bz_xmlrpc.classes.Attachment` objects
        """
        attachment_list = \
            self.bz._get_attachments([self.id])[str(self.id)]
        self._hash2attachments(attachment_list)
        return self.attachments

    def update(self, **kwargs):
        """
        Update bug with parameters from kwargs

        String parameters:

        :arg product:                   Product 
            (also updates component, version and target_milestone)
        :type product:                  `str`
        :arg component:                 Component
            (assigned_to, qa_contact gets updated)
        :type component:                `str`
        :arg version:                   Version 
        :type version:                  `str`
        :arg target_milestone:          Target Milestone
        :type target_milestone:         `str`
        :arg op_sys:                    Operating System 
        :type op_sys:                   `str`
        :arg platform:                  Platform 
        :type platform:                 `str`
        :arg summary:                   Summary
        :type summary:                  `str`
        :arg priority:                  Priority 
        :type priority:                 `str`
        :arg severity:                  Severity 
        :type severity:                 `str`
        :arg url:                       URL 
        :type url:                      `str`
        :arg whiteboard:                Whiteboard 
        :type whiteboard:               `str`
        :arg comment:                   Comment 
        :type comment:                  `str`
        :arg commentprivacy:            Private Comment
            (only in case you have provided a comment) 
        :type commentprivacy:           `boolean`
        :arg assigned_to:               Assigned to
        :type assigned_to:              `str`
        :arg qa_contact:                QA contact
        :type qa_contact:               `str`
        :arg status:                    Status
        :type status:                   `str`
        :arg resolution:                Resolution
            (only in case there is a status provided)
        :type resolution:               `str`
        :arg fixed_in:                  Fixed in Version
        :type fixed_in:                 `str`
        :arg [devel|qa|internal]_whiteboard:
        :type [devel|qa|internal]_whiteboard: `str`
        :arg [add|delete]_group:        Add/Delete Group
        :type [add|delete]_group:       `list`
        :arg [add|delete]_dependson:    Add/Delete Depends on
        :type [add|delete]_dependson:   `list`
        :arg [add|delete]_blocked:      Add/Delete Blocked
        :type [add|delete]_blocked:     `list`
        :arg [add|delete|makeexact]_keywords: 
            Add/Delete/MakeExact Keywords
        :type [add|delete|makeexact]_keywords: `list`
        :arg [add|delete]_partner:      Add/Delete Partner
        :type [add|delete]_partner:     `list`
        :arg [add|delete]_verified:     Add/Delete Varivied
        :type [add|delete]_verified:    `list`
        :arg [add|delete]_cc:           Add/Delete cc list
        :type [add|delete]_cc:          `list`
        :arg [add|delete]_alias:        Add/Delete Alias
        :type [add|delete]_alias:       `list`
        :arg cclist_accessible:    
        :type cclist_accessible:        `boolean`
        :arg reporter_accessible:    
        :type reporter_accessible:      `boolean`
        :arg dupe_id:                   Duplicate bug id
        :type dupe_id:                  `integer`

        :return: True if update worked, False if not
        :rtype: `boolean`

        Example:: 

            bug.update(
                product='Red Hat Enterprise Linux 6', 
                component='gimp',
                version='6.0', 
                target_milestone='rc', 
                add_group=['redhat']
                ) 

        """
        out = self.bz._update(self.id, kwargs)
        if out:
            self._populate(kwargs)
            return True
        else:
            return False

    def close(self, resolution, comment=None, dupe_id=None):
        """
        Convenience wrapper around update to close bugs

        :arg resolution:                Bug close resolution
        :type resolution:               `str`
        :arg comment:                   Optional comment
        :type comment:                   `str` or None
        :arg dupe_id:                   Optional Duplicate bug id
        :type comment:                   `str` or None

        :return: True if update worked, False if not
        :rtype: `boolean`
        """
        kwargs = {
            'status': 'CLOSED',
            'resolution': resolution,
        }

        if comment:
            kwargs['comment'] = comment
        if resolution == 'DUPLICATE' and dupe_id:
            kwargs['dupe_of'] = dupe_id
        return self.update(**kwargs)

    def add_comment(self, comment, private=False):
        """
        Add a comment to the bug. Pass private=True for private comment

        :arg comment:                   Optional comment
        :type comment:                   `str` or None
        :arg private:                   Private Comment
        :type private:                  `boolean`
        """
        return self.bz.add_comment(self.id, comment, private)

    def get_groups(self):
        """
        :return:                        Bugzilla group names the bug is on
        :rtype:                         `list`
        """
        if self.groups:
            return [group.name for group in self.groups if group.ison]

    def _fetch_flags(self):
        """
        Fetches Bugzilla Flags for the bug and saves in the 'flags' attribute
        """
        out = self.bz._get_flags([self.id])
        self._flags = out[str(self.id)]['bug']
        if self._flags:
            self.flags = [Flag(flag) for flag in self._flags]

    def get_flags(self):
        """
        Return Bugzilla flags for the bug
        
        :return:                        Dictionary of flags and values
        :rtype:                         `dict`
        """

        return dict([(flag.name, flag.status) for flag in self.flags])

    def update_flags(self, hash):
        """
        Updates flags for the bug
        :arg hash: Dictionary with flagname as key and state as value 

        :return: `True` if successful
        :raises: :class:`xmlrpclib.Fault` in case of invalid input.

        Example::

            bug.update_flags({
                'flag1': '+',
                'flag2': '?',
                })
        """
        return self.bz.update_flags(self.id, hash)

    def add_attachment(self, file, description, **kwargs):
        """
        Attach a file to the bug. 

        :arg file:                      Should be a filename
        :type file:                     `str`
        :arg description:               Description of this attachment
        :type description:              `str`
        :arg comment:                   (optional) 
            Comment about this attachment.
        :type comment:                  `str` or None
        :arg isprivate:                 (optional)
            True if attachment is private.
        :type isprivate:                `boolean` or None
        :arg ispatch:                   (optional)
            True if attachment is a patch.
        :type ispatch:                  `boolean` or None
        :arg contenttype:               (optional)
            Mime-type of the attached file. 
            Defaults to application/octet-stream if not set.  
        .. note:: 
            Text files will `not` be viewable in bugzilla unless you
            set `contenttype=text/plain`

        :return:                        Attachment id or None of fails.
        :rtype:                         `dict` or None  
        """
        return self.bz.add_attachment(self.id, file, description, **kwargs)

    def refresh(self):
        """
        refresh bug values
        """
        self = self.bz.get_bug(self.id)


class Comment:
    """
    Bugzilla comment object
    """
    id = ''                 #: Comment id
    author = ''             #: Author email
    bug = ''                #: :class:`~bz_xmlrpc.classes.Bug` object 
    is_private = ''         #: True if private comment
    text = ''               #: Comment body
    time = None             #: Timestamp

    def __init__(self, bug, hash):
        """
        Initialize comments

        :arg hash: Dictionary of comment details
        :arg bug: Instance of :class:`~bz_xmlrpc.classes.Bug` object

        :return: Instance of :class:`Comment`
        .. note::
            No need to use this directly. 
            Use :meth:`~bz_xmlrpc.classes.Bug.get_comments()`
        """
        self._hash = hash
        self.id = extract(hash, 'id', 'comment_id')
        self.author = extract(hash, 'email', 'author')
        self.bug = bug
        self.is_private = bool(extract(hash, 'is_private',
            'isprivate'))
        self.text = extract(hash, 'text', 'body')
        self.time = to_datetime(extract(hash, 'time', 'bug_when'))


class Attachment:
    """
    Bugzilla attachment object
    """
    id = ''                 #: Attachment id
    content_type = ''       #: Content type
    creation_time = None    #: Creation timestamp
    attacher = ''           #: Attacher email
    description = ''        #: Description
    file_name = ''          #: Filename
    bug = ''                #: :class:`~bz_xmlrpc.classes.Bug` object 
    is_private = ''         #: True if private comment
    is_obsolete = ''        #: True if attachment is obsolete 
    is_patch = ''           #: True if attachment is a patch 
    is_url = ''             #: True if attachment is a URL
    last_change_time = None #: Last modified timestamp
    fetch_url = ''          #: URL for the attachment


    def __init__(self, bug, hash):
        """
        Initialize attachments

        :arg hash: Dictionary of attachment details
        :arg bug: Instance of :class:`~bz_xmlrpc.classes.Bug` object

        :return: Instance of :class:`Attachment`
        .. note::
            No need to use this directly. 
            Use :meth:`~bz_xmlrpc.classes.Bug.get_attachments()`

        """
        self._hash = hash
        self.id = extract(hash, 'id', 'attach_id')
        self.content_type = extract(hash, 'content_type',
            'mimetype')
        self.creation_time = to_datetime(extract(hash,
            'creation_time', 'creation_ts'))
        self.attacher = extract(hash, 'attacher', 'submitter_id')
        self.description = extract(hash, 'description')
        self.file_name = extract(hash, 'file_name', 'filename')
        self.bug = bug
        self.is_private = bool(extract(hash, 'is_private',
            'isprivate'))
        self.is_obsolete = bool(extract(hash, 'is_obsolete',
            'isobsolete'))
        self.is_patch = bool(extract(hash, 'is_patch', 'ispatch'))
        self.is_url = bool(extract(hash, 'is_url', 'isurl'))
        self.last_change_time = to_datetime(extract(hash, 
            'last_change_time', 'modification_time'))

        if self.id and self.bug:
            self.fetch_url = bug.bz.url.replace('xmlrpc.cgi',
                'attachment.cgi?id=%s' % self.id)

    def fetch(self, path=None):
        """
        Fetches the attachment

        :arg path:                      Download path for the attchment
        :type path:                     `str`

        :return:                        :class:`urllib2` object of no download
            path is specified, else the full path of the downloaded file.
        """
        stream = self.bug.bz._fetch_url(self.fetch_url)
        if path:
            full_path = os.path.join(path, self.file_name)
            f = open(full_path, 'w')
            f.write(stream.read())
            f.close()
            return full_path
        else:
            return stream

class _Group:
    """
    Internal class to implement Bugzilla groups
    """
    
    def __init__(self, hash):
        """
        Initialize
        """
        self._hash = hash
        if isinstance(hash, str):
            # Hack for searched bug groups
            self.name = hash
            self.ison = True
        else:
            self.bit = extract(hash, 'bit', 'id')
            self.name = extract(hash, 'name')
            self.description = extract(hash, 'description')
            self.ingroup = bool(extract(hash, 'ingroup'))
            self.ison = bool(extract(hash, 'ison'))
            self.mandatory = bool(extract(hash, 'mandatory'))
            self.othercontrol = bool(extract(hash, 'othercontrol'))
            self.direct = bool(extract(hash, 'direct'))
            self.isbuggroup = bool(extract(hash, 'isbuggroup'))
            self.userregexp = extract(hash, 'userregexp')


class Component:
    """
    Bugzilla product component class 
    """

    def __init__(self, hash):
        """
        Initialize
        """
        self._hash = hash
        self.id = hash['id']
        self.name = hash['name']
        self.product_id = hash['product_id']
        self.product_name = hash['product_name']
        self.default_assignee = hash['default_assignee']
        self.default_cc = hash['default_cc']
        self.default_qa_contact = hash['default_qa_contact']
        self.description = hash['description']
        self.flags = hash['flags']

class User:
    """
    Bugzilla user object
    """

    def __init__(self, hash):
        """
        Initialize
        """
        self._hash = hash
        self.id = hash['id']
        self.email = hash['email']
        self.name = hash['real_name']
        self.groups = [_Group(group) for group in hash['groups']]

    def get_groups(self):
        """
        Returns group strings as a list
        """
        if self.groups:
            return [group.name for group in self.groups if group.direct]


class Flag:
    """
    Bugzilla flag object
    """

    def __init__(self, hash):
        """
        Initialize BZ flag object
        """
        self._hash = hash
        self.id = hash['id']
        self.name = hash['name']
        self.status = hash['status']
        self.setter = hash['setter']
        self.requestee = self._be('requestee')
        self.type_id = hash['type_id']
        self.last_modified = hash['modification_date']

    def _be(self, *keys):
        """
        Private conviniance wrapper around extract. 
        Hash defaults to self._hash
        """
        return extract(self._hash, *keys)
 
