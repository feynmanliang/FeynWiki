#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import os
import re
import random
import hashlib
import hmac
import json
import logging
import time
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db
from google.appengine.api import memcache

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

secret = 'In et arcu nulla, non accumsan nunc. Nullam vehicula dui.'

def wiki_key(name = 'default'):
    return db.Key.from_path('wiki', name)

class AppHandler(webapp2.RequestHandler):
    """Base handler, encapsulating jinja2."""

    def __init__(self, request=None, response=None):
        """Initialize handler."""
        super(AppHandler, self).__init__(request, response)
        self.jinja2 = jinja_env

    def write(self, string):
        """Write arbitrary string to response stream."""
        self.response.out.write(string)

    def render_str(self, template_name, values=None, **kwargs):
        """Render jinja2 template and returns as string"""
        template = self.jinja2.get_template(template_name)
        return template.render(values or kwargs)

    def render(self, template_name, values=None, **kwargs):
        """Render jinja2 template using dictionary or kwargs"""
        self.write(self.render_str(template_name, values or kwargs))

    def redirect_to(self, name, *args, **kwargs):
        """Redirect to URI that corresponds to route name"""
        self.redirect(self.uri_for(name, *args, **kwargs))

class WikiHandler(AppHandler):
    """Handler for all links in wiki application"""

    def make_secure_val(self, val):
        return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

    def check_secure_val(self, secure_val):
        val = secure_val.split('|')[0]
        if secure_val == self.make_secure_val(val):
            return val

    def set_secure_cookie(self, name, val):
        cookie_val = self.make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and self.check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        AppHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

##
## User Model
##
def users_key(group = 'default'):
        return db.Key.from_path('users', group)

def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

class User(db.Model):
    """Data model for users on blog"""
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(self, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(self, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(self, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(self, name, pw):
        u = self.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

##
## Login/Logout
##

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class Signup(WikiHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        params = dict(username = username,
                      email = email)

        if not valid_username(username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif password != verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            #make sure the user doesn't already exist
            u = User.by_name(username)
            if u:
                msg = 'That user already exists.'
                self.render('signup-form.html', error_username = msg)
            else:
                u = User.register(username, password, email)
                u.put()

                self.login(u)
                #self.redirect('/')
                self.redirect('/welcome')

class Login(WikiHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/welcome')
            #self.redirect('/')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)

class Logout(WikiHandler):
    def get(self):
        self.logout()
        self.redirect('/')
        #self.redirect('/')

class Welcome(WikiHandler):
    def get(self):
        if self.user:
            username = self.user.name
        else:
            username = "NOT LOGGED IN"
        self.render('welcome.html', username = username)

##
## Wiki Entry Model
##

class Entry(db.Model):
    name = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return self.render_str("entry.html", entry = self)

class History(Entry):
    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return self.render_str("entry.html", entry = self)



class EditEntry(WikiHandler):
    def get(self, entry_name):
        if not self.user:
            self.redirect("/signup")
        key = db.Key.from_path('Entry', str(entry_name), parent=wiki_key())
        Entry = db.get(key)
        if Entry:
            contents = Entry.content
            self.render("edit.html", name = entry_name, content = contents, error="")
        else:
            self.render("edit.html", name = entry_name, content="", error="")

    def post(self, entry_name):
        if not self.user:
            self.redirect("/signup")
        name = entry_name
        content = self.request.get('content')

        if name and content and self.user:
            key = db.Key.from_path('Entry', str(entry_name), parent=wiki_key())
            preventry = db.get(key)
            if preventry:
                h = History(parent = key, name = name, content = preventry.content)
                h.put()
            p = Entry(key_name=name, parent = wiki_key(), name = name, content = content)
            p.put()
            self.redirect('%s' % name)
        else:
            error = "content please!"
            self.render("edit.html", name = entry_name, content=content, error=error)

class WikiPage(WikiHandler):
    def get(self, entry_name):
        key = db.Key.from_path('Entry', str(entry_name), parent=wiki_key())
        Entry = db.get(key)

        if not Entry:
            self.redirect("/_edit%s" % entry_name)
            return

        self.render("permalink.html", entry = Entry)

class HistoryPage(WikiHandler):
    def get(self, entry_name):
        parentkey = db.Key.from_path('Entry', str(entry_name), parent=wiki_key())
        history = History.all().ancestor(parentkey)

        key = db.Key.from_path('Entry', str(entry_name), parent=wiki_key())
        Entry = db.get(key)

        history = history
        self.render('history.html', history = history, entry = Entry)

PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
app = webapp2.WSGIApplication([('/welcome', Welcome),
                               ('/signup', Signup),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/_edit' + PAGE_RE, EditEntry),
                               ('/_history' + PAGE_RE, HistoryPage),
                               (PAGE_RE, WikiPage)
                               ],
                              debug=True)