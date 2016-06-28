import os

import webapp2
import jinja2

import re
import logging

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
    return EMAIL_RE.match(email)

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

        check_username = valid_username(username)
        check_password = valid_password(password)
        check_email = valid_email(email)

        # things to return to the script when there are errors
        params = dict(username = username,
                      email = email)

        # run checks on username, password, email. adds error messages
        if not username or check_username is None:
            params['e_username'] = "Invalid username!"
            have_errors = True
        if not password or check_password is None:
            params['e_password'] = "Invalid password!"
            have_errors = True
        if password != verify:
            params['e_password'] = "Passwords do not match!"
        if email != '' and check_email is None:
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

app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/blog/signup', Signup),
    ('/blog/welcome', Welcome),
], debug=True)
