'''A multi user blog using Google's App Engine.'''

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
    '''Uses hash_str to return a value with the "input|inputHashed"'''
    return "%s|%s" % (s, hash_str(s))


def check_secure_val(h):
    '''Checks that input|inputHashed hasn't been modified (that input
    equals inputHashed)'''
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
    '''check if a name, pw, salt is correct
    h = salted password, salt'''
    salt = h.split(',')[1]
    return h == make_pw_hash(name, pw, salt)

# main handler


class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        '''Takes render_str and sends to the browser'''
        self.write(self.render_str(template, **kw))

    def user_logged_in(self):
        '''Return true if user is logged in.'''
        useridwithhash = self.request.cookies.get('userid')
        return useridwithhash and check_secure_val(useridwithhash)


# db items


class BlogPost(db.Model):
    '''Subject and body for a blog post.'''
    permalink = db.StringProperty(required=True)
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    postcreated = db.DateTimeProperty(auto_now_add=True)
    postedited = db.DateTimeProperty(auto_now=True)

    def render(self):
        '''replace new lines '\n' with html new lines '<br>' '''
        self.render_body = self.body.replace('\n', '<br>')
        return self.render_body


class User(db.Model):
    '''User info.'''
    username = db.StringProperty(required=True)
    password = db.StringProperty(required=True)
    email = db.EmailProperty(required=False)


# blog pages


class RedirectToMainPage(Handler):
    '''Redirect / to /blog'''
    def get(self):
        self.redirect('/blog')


class MainPage(Handler):
    '''Shows 10 newest posts.'''
    def get(self):
        posts = BlogPost.all().order('-postcreated').fetch(limit = 10)

        if posts:
            self.render('allposts.html', posts=posts)
        else:
            self.render('noposts.html')


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
        user = User.all().filter('username =', username).get()
        if user:
            params['e_username'] = "The username already exists!"
            have_errors = True

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
            # if everything is correct, hash/salt the password
            password_salted = make_pw_hash(username, password, make_salt())

            # info to send to the db to register the user
            reginfo = dict(username=username, password=password_salted)
            # add email to reginfo if it's not blank
            if email:
                reginfo['email'] = email

            # then add user to db, send to welcome page
            user = User(**reginfo)
            user.put()
            userid = str(user.key().id())

            # set a cookie with the userid|hash of userid
            self.response.headers.add_header(
                'Set-Cookie', 'userid=%s' % make_secure_val(userid)
            )
            self.redirect('/blog/welcome')


class Login(Handler):
    '''Allows a registered user to login.'''
    def get(self):
        self.render('login.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        # return error messages / username back to the login page
        params = {}

        # get info about user from database
        user = db.GqlQuery(
            "SELECT * FROM User WHERE username = :1 LIMIT 1", username
        ).get()

        # h is the hashed salted password plus the salt separated by a comma
        if user:
            h = user.password
        else:
            h = ','

        # check error possibilities
        if not username:
            params['e_username'] = "Please enter a username."
        if not password:
            params['e_password'] = "Please enter a password."
        if username and password and not valid_pw(username, password, h):
            params['e_username'] = "Incorrect username or password."

        # valid login
        if valid_pw(username, password, h):
            # set a cookie with the userid|hash of userid
            self.response.headers.add_header(
                'Set-Cookie', 'userid=%s' %
                make_secure_val(str(user.key().id()))
            )
            self.redirect('/blog/welcome')
        # anything else
        else:
            # return the username to the form
            params['username'] = username
            self.render('login.html', **params)


class Logout(Handler):
    '''Set cookie userid to empty and redirect to /blog/signup.'''
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'userid=')
        self.redirect('/blog/signup')


class Welcome(Handler):
    '''Redirected here on a successful signup.'''
    def get(self):
        useridwithhash = self.request.cookies.get('userid')
        # if no cookie, send to signup
        if not useridwithhash:
            self.redirect('/blog/signup')

        if useridwithhash and check_secure_val(useridwithhash):
            # if the userid/hash are correct in the cookie, get the username
            # by using the userid
            userid = useridwithhash.split('|')[0]
            username = User.get_by_id(int(userid)).username

            self.render('welcome.html', username=username)
        else:
            self.redirect('/blog/signup')


class CreateNewPost(Handler):
    '''For adding new posts to the blog.'''
    items = ('permalink', 'subject', 'content', 'error_subject', 'error_content')
    # create dictionary from items and set all values to empty.
    params = dict.fromkeys(items, '')

    def get(self):
        if self.user_logged_in():
            self.render('newpost.html', **CreateNewPost.params)
        else:
            self.render('noaccess.html')

    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")
        permalink = subject.replace(' ', '-')[0:50]

        if subject and content:
            post = BlogPost(permalink=permalink, subject=subject, content=content)
            post.put()
            # get new post and redirect to it
            redirect = post.key().id()
            redirectint = int(redirect)
            logging.info(redirect)
            self.redirect("/blog/%s" % redirectint)

        if not subject:
            CreateNewPost.params['error_subject'] = "A subject is required."
        if not content:
            CreateNewPost.params['error_content'] = "Content is required."
        if not subject or not content:
            # add subject and content only if there is an error
            CreateNewPost.params['subject'] = subject
            CreateNewPost.params['content'] = content
            self.render('newpost.html', **CreateNewPost.params)


class ShowPost(Handler):
    '''Show a single post from the blog.'''
    def get(self, permalink):
        postToShow = BlogPost.all().filter('permalink =', permalink).get()
        self.render('showpost.html', post=postToShow)


app = webapp2.WSGIApplication([
    ('/', RedirectToMainPage),
    ('/blog', MainPage),
    ('/blog/signup', Signup),
    ('/blog/login', Login),
    ('/blog/logout', Logout),
    ('/blog/welcome', Welcome),
    ('/blog/newpost', CreateNewPost),
    ('/blog/(.*)', ShowPost),
], debug=True)
