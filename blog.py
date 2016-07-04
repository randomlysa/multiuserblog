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

# db item(s)


class BlogPost(db.Model):
    '''Gets subject and body for a blog post.'''
    subject = db.StringProperty(required=True)
    body = db.TextProperty(required=True)
    postcreated = db.DateTimeProperty(auto_now_add=True)


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
            self.render('signup.html', **params)
        else:
            self.redirect('/blog/welcome?username=' + username)


class Welcome(Handler):
    '''Redirected here on a successful signup.'''
    def get(self):
        username = self.request.get('username')
        if valid_username(username):
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
        body = self.request.get("body")

        if subject and body:
            post = BlogPost(subject=subject, body=body)
            post.put()
            # get new post and redirect to it
            lastpost = "SELECT * from BlogPost order by postcreated desc limit 1"

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
        """
        postToShow = db.GqlQuery(
            "SELECT * FROM BlogPost WHERE ID = :1", postid
        )
        """
        postidint = int(postid)
        postToShow = BlogPost.get_by_id(postidint)
        logging.info(postToShow)

        self.render('showpost.html', post=postToShow)


app = webapp2.WSGIApplication([
    ('/', RedirectToMainPage),
    ('/blog', MainPage),
    ('/blog/signup', Signup),
    ('/blog/welcome', Welcome),
    ('/blog/newpost', CreateNewPost),
    ('/blog/(.*)', ShowPost),
], debug=True)
