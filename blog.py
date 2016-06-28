import os

import webapp2
import jinja2

import re
import logging

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(template_dir),
    autoescape=True
)

# set regular expressions for checking username, password, email
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")

def valid_username(username):
    return USER_RE.match(username)

def valid_password(password):
    return PASSWORD_RE.match(password)

def valid_email(email):
    return not email or EMAIL_RE.match(email)

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    ''' takes render_str and sends to the browser '''
    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))


class MainPage(Handler):
    def get(self):
        self.response.headers['Content-Type'] = 'text/plain'
        self.response.write('Hello, World!')


class Signup(Handler):
    def get(self):
        self.render('signup.html')

    def post(self):
        # get info from post
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        # this variable is set to True if there are any errors
        # determines if the form is reloaded (invalid) or
        # if the user is sent to the welcome page (everything is valid)
        have_errors = False

        # things to return to the script when there are errors
        params = dict(username = username,
                      email = email)

        # run checks on username, password, email. adds error messages
        if not valid_username(username):
            params['e_username'] = "Invalid username!"
            have_errors = True

        if not valid_password(password):
            params['e_password'] = "Invalid password!"
            have_errors = True
        elif password != verify:
            params['e_password'] = "Passwords do not match!"

        if not valid_email(email):
            params['e_email'] = "Invalid email!"
            have_errors = True

        if have_errors:
            self.render('signup.html', **params)
        else:
            self.redirect('/blog/welcome?username=' + username)

class Welcome(Handler):
    def get(self):
        username = self.request.get('username')
        if valid_username(username):
            self.render('welcome.html', username = username)
        else:
            self.redirect('/blog/signup')

class dbNewEntry(db.Model):
    '''Gets subject and body for a blog entry.'''
    subject = db.StringProperty(required=True)
    body = db.TextProperty(required=True)
    postcreated = db.DateTimeProperty(auto_now_add=True)

class NewEntry(Handler):
    def get(self):
        self.render('newentry.html', postsubject='', postbody='')

    def post(self):
        subject = self.request.get("subject")
        body = self.request.get("body")

        if subject and body:
            entry = dbNewEntry(subject=subject, body=body)
            entry.put()
        if not subject:
            error = "A subject is required."
        if not body:
            error = "A body is required."

app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/blog/signup', Signup),
    ('/blog/welcome', Welcome),
    ('/blog/newentry', NewEntry),
], debug=True)
