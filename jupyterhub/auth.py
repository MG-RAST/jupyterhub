"""Simple PAM authenticator"""

# Copyright (c) IPython Development Team.
# Distributed under the terms of the Modified BSD License.

import pwd
from subprocess import check_call, check_output, CalledProcessError

from tornado import gen
import simplepam

from IPython.config import LoggingConfigurable
from IPython.utils.traitlets import Bool, Set, Unicode

from .utils import url_path_join

import base64
import json
import sys
import urllib.request

class Authenticator(LoggingConfigurable):
    """A class for authentication.
    
    The API is one method, `authenticate`, a tornado gen.coroutine.
    """
    
    whitelist = Set(config=True,
        help="""Username whitelist.
        
        Use this to restrict which users can login.
        If empty, allow any user to attempt login.
        """
    )
    custom_html = Unicode('')
    
    @gen.coroutine
    def authenticate(self, handler, data):
        """Authenticate a user with login form data.
        
        This must be a tornado gen.coroutine.
        It must return the username on successful authentication,
        and return None on failed authentication.
        """
    
    def add_user(self, user):
        """Add a new user
        
        By default, this just adds the user to the whitelist.
        
        Subclasses may do more extensive things,
        such as adding actual unix users.
        """
        if self.whitelist:
            self.whitelist.add(user.name)
    
    def delete_user(self, user):
        """Triggered when a user is deleted.
        
        Removes the user from the whitelist.
        """
        if user.name in self.whitelist:
            self.whitelist.remove(user.name)
    
    def login_url(self, base_url):
        """Override to register a custom login handler"""
        return url_path_join(base_url, 'login')
    
    def logout_url(self, base_url):
        """Override to register a custom logout handler"""
        return url_path_join(base_url, 'logout')
    
    def get_handlers(self, app):
        """Return any custom handlers the authenticator needs to register
        
        (e.g. for OAuth)
        """
        return []

class LocalAuthenticator(Authenticator):
    """Base class for Authenticators that work with local *ix users
    
    Checks for local users, and can attempt to create them if they exist.
    """
    
    create_system_users = Bool(False, config=True,
        help="""If a user is added that doesn't exist on the system,
        should I try to create the system user?
        """
    )
    
    def add_user(self, user):
        """Add a new user
        
        By default, this just adds the user to the whitelist.
        
        Subclasses may do more extensive things,
        such as adding actual unix users.
        """
        if not self.system_user_exists(user):
            if self.create_system_users:
                self.add_system_user(user)
            else:
                raise KeyError("User %s does not exist." % user.name)
        
        super(LocalAuthenticator, self).add_user(user)
    
    @staticmethod
    def system_user_exists(user):
        """Check if the user exists on the system"""
        try:
            pwd.getpwnam(user.name)
        except KeyError:
            return False
        else:
            return True
    
    @staticmethod
    def add_system_user(user):
        """Create a new *ix user on the system. Works on FreeBSD and Linux, at least."""
        name = user.name
        for useradd in (
            ['pw', 'useradd', '-m'],
            ['useradd', '-m'],
        ):
            try:
                check_output(['which', useradd[0]])
            except CalledProcessError:
                continue
            else:
                break
        else:
            raise RuntimeError("I don't know how to add users on this system.")
    
        check_call(useradd + [name])


class PAMAuthenticator(LocalAuthenticator):
    """Authenticate local *ix users with PAM"""
    encoding = Unicode('utf8', config=True,
        help="""The encoding to use for PAM"""
    )
    service = Unicode('login', config=True,
        help="""The PAM service to use for authentication."""
    )
    
    @gen.coroutine
    def authenticate(self, handler, data):
        """Authenticate with PAM, and return the username if login is successful.
    
        Return None otherwise.
        """
        username = data['username']
        if self.whitelist and username not in self.whitelist:
            return
        # simplepam wants bytes, not unicode
        # see simplepam#3
        busername = username.encode(self.encoding)
        bpassword = data['password'].encode(self.encoding)
        if simplepam.authenticate(busername, bpassword, service=self.service):
            return username
    
class GlobusAuthenticator(LocalAuthenticator):
    """Authenticate local *ix users with Globus"""
    encoding = Unicode('utf8', config=True,
        help="""The encoding to use for Globus"""
    )
    service = Unicode('login', config=True,
        help="""The PAM service to use for authentication."""
    )

    @staticmethod
    def obj_from_url(url, auth=None, data=None, debug=False):
        header = {'Accept': 'application/json'}
        if auth:
            header['Authorization'] = auth
        if data:
            header['Content-Type'] = 'application/json'
        if debug:
            if data:
                print("data:\t"+data)
            print("header:\t"+json.dumps(header))
            print("url:\t"+url)
        try:
            req = urllib.request.Request(url, data, headers=header)
            res = urllib.request.urlopen(req).read().decode("utf-8")
        except urllib.error.HTTPError as error:
            try:
                eobj = json.loads(error.read())
                sys.stderr.write("ERROR (%s): %s\n" %(error.code, eobj['ERROR']))
                sys.exit(1)
            except:
                sys.stderr.write("ERROR (%s): %s\n" %(error.code, error.read()))
                sys.exit(1)
        if not res:
            sys.stderr.write("ERROR: no results returned\n")
            sys.exit(1)
        obj = json.loads(res)
        if obj is None:
            sys.stderr.write("ERROR: return structure not valid json format\n")
            sys.exit(1)
        if len(obj.keys()) == 0:
            sys.stderr.write("ERROR: no data available\n")
            sys.exit(1)
        if 'ERROR' in obj:
            sys.stderr.write("ERROR: %s\n" %obj['ERROR'])
            sys.exit(1)
        return obj

    @gen.coroutine
    def authenticate(self, handler, data):
        """Authenticate with Globus, and return the username if login is successful.
    
        Return None otherwise.
        """
        username = data['username']
        if self.whitelist and username not in self.whitelist:
            return
        passwd = data['password']

        auth = "Basic " + (base64.b64encode(bytes(username, 'utf-8') + b':' + bytes(passwd, 'utf-8'))).decode('utf-8')
        data = self.obj_from_url("https://nexus.api.globusonline.org/goauth/token?grant_type=client_credentials", auth=auth)
        if "user_name" in data:
            return data["user_name"]
