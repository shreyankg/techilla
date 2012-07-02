# Copyright 2010 Red Hat Inc.
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
    The Bugzilla Bug Object
    -----------------------

    Attributes:
    -----------
    bz                  : Points to the BugzillaBase instance for the bug

    id                  : bug id
    summary             : Bug summary
    description         : Bug description
    assigned_to         : Assigned to Bugzilla login
    qa_contact          : QA Contact Bugzilla login
    reporter            : Reported By Bugzilla login
    product             : Product
    component           : Component
    creation_time       : Bug creation time, datetime
    last_change_time    : Last modified time, datetime
    dupe_of             : Duplicate of bug id
    priority            : Bug Priority
    severity            : Bug Severity
    partner             : Partners - array
    target_milestone    : Target milestone
    status              : Bug Status
    resolution          : Resulotion of closed bug
    whiteboard          : Bug status whiteboard
    version             : Version of platform
    platform            : Platform architecture
    keywords            : Array of keywords
    fixed_in            : Fixed in version

    comments            : Array of Comment objects, incuding bug description.
    attachments         : Array of Attachment objects
    groups              : Array of Group objects
    flags               : Array of Flag objects

    """

    def __init__(self, hash, bz):
        """
        Initialise a bug object

        A hash of bug attributes and a BugzillaBase object needs to be passed
        as parameters.
        """

        self.bz = bz

        self.id = 0
        self.summary = ''
        self.description = ''
        self.assigned_to = ''
        self.qa_contact = ''
        self.reporter = ''
        self.product = ''
        self.component = ''
        self.creation_time = ''
        self.last_change_time = ''
        self.dupe_of = 0
        self.priority = ''
        self.severity = ''
        self.partner = ''
        self.target_milestone = ''
        self.status = ''
        self.whiteboard = ''
        self.resolution = ''
        self.version = 0
        self.platform = ''
        self.keywords = []
        self.fixed_in = ''
        self.comments = []
        self.attachments = []
        self.groups = []
        self.flags = []
        
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

        self._comments = self._be('longdescs')
        if self._comments:
            self._hash2comments(self._comments)

        self._attachments = self._be('attachments')
        if self._attachments:
             self._hash2attachments(self._attachments)

        self._groups = self._be( 'groups')
        if self._groups:
            self.groups = [_Group(group) for group in self._groups]

        self._flags = self._be('flag_types')
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
        """
        attachment_list = \
            self.bz._get_attachments([self.id])[str(self.id)]
        self._hash2attachments(attachment_list)
        return self.attachments

    def update(self, **kwargs):
        """
        Update bug with parameters from kwargs

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
        [add|delete]_group              (array)
        [add|delete]_dependson          (array)
        [add|delete]_blocked            (array)
        [add|delete|makeexact]_keywords (array)
        [add|delete]_partner            (array)
        [add|delete]_verified           (array)
        [add|delete]_cc                 (array)
        [add|delete]_alias              (array)
        [devel|qa|internal]_whiteboard  (string)
        [cclist|reporter]_accessible    (boolean)

        eg: 
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
        Optional arg: comment
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
        Add a comment to the bug
        pass private=True for private comment
        """
        hash = {
            'id': self.id,
            'comment': comment,
            }
        if private:
            hash['private'] = True
        out = self.bz._proxy.Bug.add_comment(hash)
        if out:
            return out['id']
        else:
            return False

    def get_groups(self):
        """
        Returns Bugzilla group names the bug is on, as a list
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

    def get_flags(self, fetch=False):
        """
        Return Bugzilla flags for the bug in dict format
        pass fetch=True in order to fetch the flags from Bugzilla
        
        NOTE/TODO: Does not return needinfo flags
        """
        if fetch:
            self._fetch_flags()

        return dict([(flag.name, flag.subflags[0].status) for flag in self.flags if
            (flag.is_active and flag.subflags )])

    def update_flags(self, hash):
        """
        Updates flags for the bug
        hash is a dictionary with flagname as key and state as value 
        e.g. {
            'flag1': '+',
            'flag2': '?',
            }

        NOTE/TODO: Does not work with needinfo flags
        """
        return self.bz.update_flags(self.id, hash)

    def add_attachment(self, file, description, **kwargs):
        """
        Attach a file to the bug. Returns the ID of the attachment
        or returns None if something goes wrong.

        Compulsory arguements:
        ----------------------
        file            : should be a filename.
        description     : is the short description of this attachment.

        Optional arguements:
        --------------------
        comment         : A comment about this attachment.
        isprivate       : Set to True if the attachment should be marked private.
        ispatch         : Set to True if the attachment is a patch.
        contenttype     : The mime-type of the attached file. Defaults to
                          application/octet-stream if not set. 
                     NOTE: text files will *not* be viewable in bugzilla 
                     unless you remember to set this to text/plain.
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
    def __init__(self, bug, hash):
        """
        Initialize comments
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
    def __init__(self, bug, hash):
        """
        Initialize attachments
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
        self.fetch_url = ''
        if self.id and self.bug:
            self.fetch_url = bug.bz.url.replace('xmlrpc.cgi',
                'attachment.cgi?id=%s' % self.id)

    def fetch(self, path=None):
        """
        Fetches the attachment
        returns a urllib2 object of no download path is specified
        otherwise it returns the full path of the downloaded file.
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
    Bugzilla product component object
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
        Initialize
        """
        self._hash = hash
        self.id = hash['id']
        self.name = hash['name']
        self.description = hash['description']
        self.is_active = bool(hash['is_active'])
        self.subflags = [_SubFlag(subflag) for subflag in hash['flags']]


class _SubFlag:
    """
    Private Class for atomic subflags
    """

    def __init__(self, hash):
        """
        Initialize
        """
        self._hash = hash
        self.id = hash['id']
        self.requestee = extract(hash, 'requestee_email', 'requestee_id')
        self.setter = extract(hash, 'setter_email', 'setter_id')
        self.status = hash['status']
