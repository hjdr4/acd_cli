import os
import json
import requests
import time
import logging
import webbrowser
import datetime
import random
import string
from requests.auth import AuthBase
from threading import Lock

logger = logging.getLogger(__name__)

TOKEN_INFO_URL = 'https://api.amazon.com/auth/o2/tokeninfo'

def create_handler(path: str):
    return AppspotOAuthHandler(path)

class Serializable:
    def toJSON(self):
        return json.dumps(self,default=lambda o: o.__dict__,
                    sort_keys=True, indent=4)
           
    def fromJSON(self,j):
        self.__dict__=json.loads(j)
        return self

class Token(Serializable):
    def __init__(self):
        self.access_token=None
        self.token_type="bearer"
        self.refresh_token=None
        self.expiry=None
        
def utc2local (utc):
    epoch = time.mktime(utc.timetuple())
    offset = datetime.datetime.fromtimestamp (epoch) - datetime.datetime.utcfromtimestamp (epoch)
    return utc + offset

def rfc3339NanoUTCToDatetime(s):
    _input=s[0:19]
    return utc2local(datetime.datetime.strptime(_input, '%Y-%m-%dT%H:%M:%S'))

def datetimeTorfc3339NanoUTC(d: datetime.datetime):
    return d.utcnow().isoformat("T")+"000Z"
    
class OAuthHandler(AuthBase):
    OAUTH_DATA_FILE = 'oauth_data'

    def __init__(self, path):
        self.path = path
        self.token=Token()
        self.oauth_data_path = os.path.join(path, self.OAUTH_DATA_FILE)
        self.init_time = time.time()
        self.lock = Lock()

    def __call__(self, r: requests.Request):
        with self.lock:
            r.headers['Authorization'] = self.get_auth_token()
        return r
    
    @property
    def exp_time(self):
        return rfc3339NanoUTCToDatetime(self.token.expiry).timestamp()

    @classmethod
    def validate(cls, oauth: str):
        """Deserialize and validate an OAuth string

        :raises: RequestError"""

        from .common import RequestError

        try:
            o = Token().fromJSON(oauth)
            o.access_token
            o.refresh_token
            o.expiry
            return o
        except (Exception) as e:
            logger.critical('Invalid authentication token: Invalid JSON or missing key.'
                            'Token:\n%s' % oauth)
            raise RequestError(RequestError.CODE.INVALID_TOKEN, e.__str__())

    def treat_auth_token(self, time_: float):
        """Adds expiration time to member OAuth dict using specified begin time."""
        exp_time = time_ + rfc3339NanoUTCToDatetime(self.token.expiry).timestamp() - 120
        self.token.expiry = datetimeTorfc3339NanoUTC(datetime.datetime.fromtimestamp(exp_time))
        logger.info('New token expires at %s.'
                    % datetime.datetime.fromtimestamp(exp_time).isoformat(' '))

    def load_oauth_data(self):
        """Loads oauth data file, validate and add expiration time if necessary"""
        self.check_oauth_file_exists()

        with open(self.oauth_data_path) as oa:
            o = oa.read()
        try:
            self.token = self.validate(o)
        except:
            logger.critical('Local OAuth data file "%s" is invalid. '
                            'Please fix or delete it.' % self.oauth_data_path)
            raise
        
        if not self.token.expiry:
            self.treat_auth_token(self.init_time)
            self.write_oauth_data()
        else:
            self.get_auth_token(reload=False)

    def get_auth_token(self, reload=True) -> str:
        """Gets current access token, refreshes if necessary.

        :param reload: whether the oauth token file should be reloaded (external update)"""

        if time.time() > self.exp_time:
            logger.info('Token expired at %s.'
                        % datetime.datetime.fromtimestamp(self.exp_time).isoformat(' '))

            # if multiple instances are running, check for updated file
            if reload:
                with open(self.oauth_data_path) as oa:
                    o = oa.read()
                self.oauth_data = self.validate(o)

            if time.time() > self.exp_time:
                self.refresh_auth_token()
            else:
                logger.info('Externally updated token found in oauth file.')
        return "Bearer " + self.token.access_token

    def write_oauth_data(self):
        """Dumps (treated) OAuth dict to file as JSON."""

        new_nm = self.oauth_data_path + ''.join(random.choice(string.hexdigits) for _ in range(8))
        rm_nm = self.oauth_data_path + ''.join(random.choice(string.hexdigits) for _ in range(8))

        f = open(new_nm, 'w')
        f.write(self.token.toJSON())
        f.flush()
        os.fsync(f.fileno())
        f.close()

        if os.path.isfile(self.oauth_data_path):
            os.rename(self.oauth_data_path, rm_nm)
        os.rename(new_nm, self.oauth_data_path)
        try:
            os.remove(rm_nm)
        except OSError:
            pass

    def refresh_auth_token(self):
        """Fetches a new access token using the refresh token."""
        raise NotImplementedError

    def check_oauth_file_exists(self):
        """Checks for OAuth file existence and one-time initialize if necessary. Throws on error."""
        raise NotImplementedError

    def get_access_token_info(self) -> dict:
        """
        :returns:
        int exp: expiration time in sec,
        str aud: client id
        user_id, app_id, iat (exp time)"""

        r = requests.get(TOKEN_INFO_URL,
                         params={'access_token': self.token.access_token})
        return r.json()


class AppspotOAuthHandler(OAuthHandler):
    APPSPOT_URL = 'https://go-acd.appspot.com/'
    APPSPOT_REFRESH_URL = 'https://go-acd.appspot.com/refresh'
    
    def __init__(self, path):
        super().__init__(path)
        self.load_oauth_data()

        logger.info('%s initialized' % self.__class__.__name__)

    def check_oauth_file_exists(self):
        """Checks for existence of oauth token file and instructs user to visit
        the Appspot page if it was not found.

        :raises: FileNotFoundError if oauth file was not placed into cache directory"""

        if os.path.isfile(self.oauth_data_path):
            return

        input('For the one-time authentication a browser (tab) will be opened at %s.\n'
              % AppspotOAuthHandler.APPSPOT_URL + 'Please accept the request and ' +
              'save the plaintext response data into a file called "%s" ' % self.OAUTH_DATA_FILE +
              'in the directory "%s".\nPress a key to open a browser.\n' % self.path)
        webbrowser.open_new_tab(AppspotOAuthHandler.APPSPOT_URL)

        input('Press a key if you have saved the "%s" file into "%s".\n'
              % (self.OAUTH_DATA_FILE, self.path))

        with open(self.oauth_data_path):
            pass

    def refresh_auth_token(self):
        """:raises: RequestError"""

        logger.info('Refreshing authentication token.')

        ref = self.token.toJSON()
        t = time.time()

        from .common import RequestError, ConnectionError

        try:
            response = requests.post(self.APPSPOT_REFRESH_URL, data=ref)
        except ConnectionError as e:
            logger.critical('Error refreshing authentication token.')
            raise RequestError(RequestError.CODE.CONN_EXCEPTION, e.__str__())

        if response.status_code != requests.codes.ok:
            raise RequestError(RequestError.CODE.REFRESH_FAILED,
                               'Error refreshing authentication token: %s' % response.text)

        r = self.validate(response.text)

        self.token = r
        self.treat_auth_token(t)
        self.write_oauth_data()

