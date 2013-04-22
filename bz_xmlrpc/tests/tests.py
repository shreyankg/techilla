# Copyright 2010, 2012 Red Hat Inc.
# Author: Shreyank Gupta <sgupta@redhat.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
# the full text of the license.

import unittest
import random
import os.path
from bz_xmlrpc.base import BugzillaBase
from bz_xmlrpc.classes import Bug
from bz_xmlrpc import settings


# Global Bugzilla level test values
USER = settings.USER['username']
PASSWORD = settings.USER['password']

BUGZILLA_URL = settings.BUGZILLA_URL 


# Original bug test values
B = {
    'summary': 'Test Summary',
    'product': 'Fedora',
    'component': 'rpm',
    'version': '18',
    'description': 'Hello World',
    'platform': 'x86_64',
    'priority': 'low',
    'severity': 'urgent',
    'whiteboard': '3-2-1',
    'assigned_to': 'sgupta@redhat.com',
    'qa_contact': 'swgoswam@redhat.com',
    'reporter': USER,
    'status': 'NEW',
    'target_milestone': '---',
    }

# Update bug test values
U = {
    'summary': 'New Summary',
    'product': 'Fedora EPEL',
    'component': 'cairomm',
    'version': 'el5',
    'platform': 'i386',
    'target_milestone': '---',
    'priority': 'high',
    'severity': 'low',
    'whiteboard': '1-2-3',
    'keywords': ['Documentation'],
    'groups': ['redhat'],
    'comment': '''Test Comment.
Second line.''',
    'comment2': '''Another test comment.
Another line''',
    'comment3': '''Closed WONTFIX.
Line two''',
    'commentprivacy': True,
    'status': 'ON_DEV',
    'resolution': 'WONTFIX',
    'flags': {
        'needinfo': '+',
        },
    }

# Attachment related values

A = {
    'path': '/tmp',
    'name': 'attach.txt',
    'text': """Contents for test attachment.
Line two""",
    'description': 'Test Attachment',
    'comment': """Attached file attach.txt.
New line""",
    'commentprivacy': True,
    'content_type': 'text/plain',
    }

ALPHABET = 'abcdefghijklmnopqrstuvwxyz_0123456789'
MAX_WORD_LENGTH = 15

def random_word(length=0):
    """
    Genarates a random word
    """
    if not length:
        length = int(random.random() * MAX_WORD_LENGTH)
    return ''.join(random.sample(ALPHABET, length))

def random_sentence(words=2):
    """
    Genarates a random sentence
    """
    return ' '.join([random_word() for each in range(words)])
    

class TestBug(unittest.TestCase):
    
    def setUp(self):
        # if not self.bug:
        self.bz = BugzillaBase(
            user=USER,
            password=PASSWORD,
            url=BUGZILLA_URL
            )
        # Create bug 
        self.bug = self.bz.create(
            product=B['product'],
            component=B['component'],
            summary=B['summary'],
            version=B['version'],
            description=B['description'],
            platform=B['platform'],
            priority=B['priority'],
            severity=B['severity'],
            whiteboard=B['whiteboard'],
            assigned_to=B['assigned_to'],
            qa_contact=B['qa_contact']
            )
        print self.bug.url

    def test_create(self):
        self.assertTrue(self.bug != None)

    def test_get_bug(self):
        self.bug = self.bz.get_bug(self.bug.id)

        self.assertEqual(self.bug.product, B['product'])
        self.assertEqual(self.bug.component, [B['component']])
        self.assertEqual(self.bug.summary, B['summary'])
        self.assertEqual(self.bug.version, [B['version']])
        self.assertEqual(self.bug.description, B['description'])
        self.assertEqual(self.bug.platform, B['platform'])
        self.assertEqual(self.bug.priority, B['priority'])
        self.assertEqual(self.bug.severity, B['severity'])
        self.assertEqual(self.bug.whiteboard, B['whiteboard'])
        self.assertEqual(self.bug.assigned_to, B['assigned_to'])
        self.assertEqual(self.bug.qa_contact, B['qa_contact'])

    def test_update(self):
        
        self.bug.update(
            summary=U['summary'],
            product=U['product'],
            component=U['component'],
            version=U['version'],
            platform=U['platform'],
            target_milestone=U['target_milestone'],
            priority=U['priority'],
            severity=U['severity'],
            whiteboard=U['whiteboard'],
            add_keywords=U['keywords'],
            add_groups=U['groups'],
            comment=U['comment'],
            commentprivacy=U['commentprivacy'],
            status=U['status']
            )
        # Get bug again to verify
        self.bug = self.bz.get_bug(self.bug.id, comments=True)

        self.assertEqual(self.bug.summary, U['summary'])
        self.assertEqual(self.bug.product, U['product'])
        self.assertEqual(self.bug.component, [U['component']])
        self.assertEqual(self.bug.version, [U['version']])
        self.assertEqual(self.bug.platform, U['platform'])
        self.assertEqual(self.bug.target_milestone, U['target_milestone'])
        self.assertEqual(self.bug.priority, U['priority'])
        self.assertEqual(self.bug.severity, U['severity'])
        self.assertEqual(self.bug.whiteboard, U['whiteboard'])
        self.assertComment(U['comment'], U['commentprivacy'])
        self.assertEqual(self.bug.status, U['status'])

        #Component.get is broken, hence commenting out this part of the test
        """
        component = self.bz.component(U['product'], U['component'])
        self.assertEqual(self.bug.assigned_to, component.default_assignee)
        self.assertEqual(self.bug.qa_contact, component.default_qa_contact)
        """

        for keyword in U['keywords']:
            self.assertTrue(keyword in self.bug.keywords)
        for group in U['groups']:
            self.assertTrue(group in self.bug.get_groups())

    def test_close(self):
        self.bug.close(U['resolution'], comment=U['comment3'])
        # Now test
        self.bug = self.bz.get_bug(self.bug.id, comments=True)
        comments = [comment.text for comment in self.bug.comments]
        self.assertEqual(self.bug.status, 'CLOSED')
        self.assertEqual(self.bug.resolution, U['resolution'])
        self.assertComment(U['comment3'])

    def test_add_comment(self):
        self.bug.add_comment(U['comment2'], private=U['commentprivacy'])
        # Fetch comments
        self.bug.get_comments()
        self.assertComment(U['comment2'], U['commentprivacy'])

    def test_flags(self):
        self.bug.update_flags(U['flags'])
        # Fetch bug
        self.bug = self.bz.get_bug(self.bug.id)
        flags = self.bug.get_flags()
        for key, value in U['flags'].iteritems():
            self.assertTrue(flags.has_key(key))
            self.assertEqual(flags[key], value)

    def test_attachment(self):
        # make new attachment file
        path = os.path.join(A['path'], A['name'])
        f = open(path, 'w')
        f.write(A['text'])
        f.close()
        
        # attach it
        id = self.bug.add_attachment(
            path, 
            A['description'],
            comment=A['comment'],
            isprivate=A['commentprivacy'],
            contenttype=A['content_type'],
            )['ids'][0]
        # fetch
        self.bug = self.bz.get_bug(self.bug.id, comments=True,
                attachments=True)
        attachments = self.bug.attachments
        attach_ids = [attachment.id for attachment in attachments]
        # test
        self.assertTrue(id in attach_ids)
        attachment = attachments[attach_ids.index(id)]
        self.assertEqual(attachment.fetch().read(), A['text'])
        self.assertEqual(attachment.file_name, A['name'])
        self.assertEqual(attachment.description, A['description'])
        self.assertEqual(attachment.content_type, A['content_type'])
        flag = 0
        for comment in self.bug.comments:
            if comment.text.find(A['comment']) != -1:
                flag = self.bug.comments.index(comment)
        self.assertTrue(flag != 0)
        self.assertEqual(self.bug.comments[flag].is_private, 
            A['commentprivacy'])

    def assertComment(self, test_value, test_privacy=None):
        """
        Asserts for properly updated comments
        """
        comments = [comment.text for comment in self.bug.comments]
        self.assertTrue(test_value in comments)
        if test_privacy != None:
            comment_index = comments.index(test_value)
            self.assertEqual(self.bug.comments[comment_index].is_private,
                test_privacy)

    def tearDown(self):
        self.bz.logout()

class TestSearch(unittest.TestCase):
    
    def setUp(self):
        self.bz = BugzillaBase(
            user=USER,
            password=PASSWORD,
            url=BUGZILLA_URL
            )

    def test_search(self):
        bugs = self.bz.search(
            product=B['product'],
            component=B['component'],
            summary=B['summary'],
            assigned_to=B['assigned_to'],
            qa_contact=B['qa_contact'],
            status=B['status'],
            platform=B['platform'],
            priority=B['priority'],
            severity=B['severity'],
            reporter=B['reporter'],
            whiteboard=B['whiteboard'],
            target_milestone=B['target_milestone'],
            version=B['version'],
            )
        print [bug.id for bug in bugs]
        for bug in bugs:
            self.assertEqual(bug.product, B['product'])
            self.assertEqual(bug.component, [B['component']])
            self.assertEqual(bug.summary, B['summary'])
            self.assertEqual(bug.assigned_to, B['assigned_to']),
            self.assertEqual(bug.status, B['status'])
            self.assertEqual(bug.qa_contact, B['qa_contact'])
            self.assertEqual(bug.platform, B['platform'])
            self.assertEqual(bug.priority, B['priority'])
            self.assertEqual(bug.severity, B['severity'])
            self.assertEqual(bug.reporter, B['reporter'])
            self.assertEqual(bug.whiteboard, B['whiteboard'])
            self.assertEqual(bug.version, [B['version']])
            self.assertEqual(bug.target_milestone, B['target_milestone'])

    def test_consistancy(self):
        # Take some random values
        summary = random_sentence(3)
        description = '\n'.join([random_sentence(4) for each in range(4)])
        whiteboard = random_word(30)
        # Create bug 
        self.bug = self.bz.create(
            product=B['product'],
            component=B['component'],
            summary=summary,
            version=B['version'],
            description=description,
            platform=B['platform'],
            priority=B['priority'],
            severity=B['severity'],
            whiteboard=whiteboard,
            assigned_to=B['assigned_to'],
            qa_contact=B['qa_contact']
            )
        print self.bug.url

        # Search Bug
        bugs = self.bz.search(
            product=B['product'],
            component=B['component'],
            summary=summary,
            assigned_to=B['assigned_to'],
            qa_contact=B['qa_contact'],
            platform=B['platform'],
            priority=B['priority'],
            severity=B['severity'],
            reporter=B['reporter'],
            version=B['version'],
            )
        # Check if the filed bug is present in search 
        ids = [bug.id for bug in bugs]
        self.assertTrue(self.bug.id in ids)

        # Assert bug fields 
        bug = bugs[ids.index(self.bug.id)]
        self.assertEqual(bug.product, B['product'])
        self.assertEqual(bug.component, [B['component']])
        self.assertEqual(bug.summary, summary)
        self.assertEqual(bug.version, [B['version']])
        self.assertEqual(bug.description.strip(), description)
        self.assertEqual(bug.platform, B['platform'])
        self.assertEqual(bug.priority, B['priority'])
        self.assertEqual(bug.severity, B['severity'])
        self.assertEqual(bug.whiteboard, whiteboard)
        self.assertEqual(bug.assigned_to, B['assigned_to'])
        self.assertEqual(bug.qa_contact, B['qa_contact'])

    def tearDown(self):
        self.bz.logout()


def bug_suite():
    suite = unittest.TestLoader().loadTestsFromTestCase(TestBug)
    unittest.TextTestRunner(verbosity=3).run(suite)

def search_suite():
    suite = unittest.TestLoader().loadTestsFromTestCase(TestSearch)
    unittest.TextTestRunner(verbosity=3).run(suite) 
