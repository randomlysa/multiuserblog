import os

import webapp2
import jinja2

import re
import logging

import hmac  # to secure cookies
import random  # to make a salt for passwords
import string
import hashlib

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

# set secret for securing cookies
SECRET = 'secretkeyhere'

# functions to secure / check cookies


def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()


def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))


def check_secure_val(h):
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val


# make a salt for securing passwords
def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))


def make_pw_hash(name, pw, salt = None):
    '''make a salt for a new name, pw or
    verify if a passed in name, pw, salt is correct'''
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (h, salt)


def valid_pw(name, pw, h):
    '''check if a name, pw, salt is correct'''
    salt = h.split('.')[1]
    return h == make_pw_hash(name, pw, salt)

# db item(s)


class BlogPost(db.Model):
    '''Subject and body for a blog post.'''
    subject = db.StringProperty(required=True)
    body = db.TextProperty(required=True)
    postcreated = db.DateTimeProperty(auto_now_add=True)


class User(db.Model):
    '''User info.'''
    username = db.StringProperty(required=True)
    password = db.StringProperty(required=True)
    email = db.EmailProperty(default='')

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        '''Takes render_str and sends to the browser'''
        self.write(self.render_str(template, **kw))


class RedirectToMainPage(Handler):
    '''Redirect / to /blog'''
    def get(self):
        self.redirect('/blog')


class MainPage(Handler):
    '''Shows 10 newest posts.'''
    def get(self):
        entries = db.GqlQuery(
            "SELECT * FROM BlogPost ORDER BY postcreated DESC LIMIT 10"
        )
        logging.info(entries)
        self.render('main.html', entries=entries)


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
        params = dict(username=username, email=email)

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
            # send back to the signup page on errors
            self.render('signup.html', **params)
        else:
            # if everything is correct, add user to db, send to welcome page
            user = User(username=username, password=password, email=email)
            user.put()
            userid = str(user.key().id())

            # set a cookie with the userid|hash of userid
            self.response.headers.add_header(
                'Set-Cookie', 'userid=%s' % make_secure_val(userid)
            )
            self.redirect('/blog/welcome')


class Welcome(Handler):
    '''Redirected here on a successful signup.'''
    def get(self):
        useridwithhash = self.request.cookies.get('userid')
        if check_secure_val(useridwithhash):
            # if the userid/hash are correct in the cookie, get the username
            # by using the userid
            userid = useridwithhash.split('|')[0]
            username = User.get_by_id(int(userid)).username

            self.render('welcome.html', username = username)
        else:
            self.redirect('/blog/signup')


class CreateNewPost(Handler):
    '''For adding new entries to the blog.'''
    items = ('subject', 'body', 'error_subject', 'error_body')
    # create dictionary from items and set all values to empty.
    params = dict.fromkeys(items, '')

    def get(self):
        self.render('newpost.html', **CreateNewPost.params)

    def post(self):
        subject = self.request.get("subject")
        body = self.request.get("content")

        if subject and body:
            post = BlogPost(subject=subject, body=body)
            post.put()
            # get new post and redirect to it
            redirect = post.key().id()
            redirectint = int(redirect)
            logging.info(redirect)
            self.redirect("/blog/%s" % redirectint)

        if not subject:
            CreateNewPost.params['error_subject'] = "A subject is required."
        if not body:
            CreateNewPost.params['error_body'] = "A body is required."
        if not subject or not body:
            # add subject and body only if there is an error
            CreateNewPost.params['subject'] = subject
            CreateNewPost.params['body'] = body
            self.render('newpost.html', **CreateNewPost.params)


class ShowPost(Handler):
    '''Show a single post from the blog.'''
    def get(self, postid):
        postToShow = BlogPost.get_by_id(int(postid))
        self.render('showpost.html', post=postToShow)


app = webapp2.WSGIApplication([
    ('/', RedirectToMainPage),
    ('/blog', MainPage),
    ('/blog/signup', Signup),
    ('/blog/welcome', Welcome),
    ('/blog/newpost', CreateNewPost),
    ('/blog/(.*)', ShowPost),
], debug=True)
