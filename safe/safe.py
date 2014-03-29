import os
import gnupg
import boto
import json
from boto.s3 import connection as s3


class Safe(object):
  SAFE_CONFIG_FILE = os.path.expanduser('~/.saferc')
  GPG_EMAIL_CONFIG_KEY = 'gpg_email'

  AWS_ACCESS_CONFIG_KEY = 'aws_access_key'
  AWS_SECRET_ACCESS_CONFIG_KEY = 'aws_secret_access_key'
  SCORYST_SAFE_BUCKET = 'scoryst-safe'

  def __init__(self):
    """ Creates a Safe that contains locked documents. """
    # set up GPG and S3 interfaces
    self.gpg = gnupg.GPG(use_agent=True)
    self._fetch_config_options()
    self._establish_s3_connection()


  def _fetch_config_options(self):
    """ Retrieves the GPG email for the current user. """
    if os.path.isfile(self.SAFE_CONFIG_FILE):
      # config file exists; read in options
      handle = open(self.SAFE_CONFIG_FILE, 'r')
      config_contents = handle.read()
      handle.close()

      try:
        config = json.loads(str(self.gpg.decrypt(config_contents)))
      except :
        # bad config file; redo configuration as if file didn't exist
        os.remove(self.SAFE_CONFIG_FILE)
        return self._fetch_config_options()
      else:
        self.gpg_email = config[self.GPG_EMAIL_CONFIG_KEY]
        self.aws_access_key = config[self.AWS_ACCESS_CONFIG_KEY]
        self.aws_secret_access_key = config[self.AWS_SECRET_ACCESS_CONFIG_KEY]
    else:
      # no config file; ask for user input and remember it
      self.gpg_email = raw_input('Enter your GPG key email: ')
      self.aws_access_key = raw_input('Enter your AWS access key: ')
      self.aws_secret_access_key = raw_input('Enter your AWS secret key: ')

      config = {
        self.GPG_EMAIL_CONFIG_KEY: self.gpg_email,
        self.AWS_ACCESS_CONFIG_KEY: self.aws_access_key,
        self.AWS_SECRET_ACCESS_CONFIG_KEY: self.aws_secret_access_key,
      }

      # we're storing sensitive AWS keys, so encrypt them first
      config_contents = self.gpg.encrypt(json.dumps(config), self.gpg_email)
      with open(self.SAFE_CONFIG_FILE, 'w') as handle:
        handle.write(str(config_contents))


  def _establish_s3_connection(self):
    """ Establishes a connection with S3 using environment variables. """
    connection = s3.S3Connection(self.aws_access_key, self.aws_secret_access_key)
    self.bucket = connection.get_bucket(self.SCORYST_SAFE_BUCKET)


  def store(self, document_name, document_text, recipient=None):
    """
    Encrypts the given text and stores it in a document with the provided name.
    Encrypts it for the given recipient. If recipient is not specified, encrypts
    it for the default gpg email.
    """
    # encrypt text
    document_text = document_text.strip()
    recipient = recipient if not recipient == None else self.gpg_email
    encrypted_text = self.gpg.encrypt(document_text, recipient)

    # store in S3
    key = s3.Key(self.bucket)
    key.key = '%s/%s' % (recipient, document_name)
    key.set_contents_from_string(str(encrypted_text))


  def read(self, document_name):
    """ Decrypts and reads the given document. """
    # fetch encrypted text from S3 and decrypt
    key = s3.Key(self.bucket)
    key.key = '%s/%s' % (self.gpg_email, document_name)

    try:
      encrypted_text = key.get_contents_as_string()
    except boto.exception.S3ResponseError:
      return None
    else:
      return str(self.gpg.decrypt(encrypted_text))


  def list(self):
    """ Lists all locked documents. """
    # find all files in the encrypted directory
    keys = self.bucket.list('%s/' % self.gpg_email)
    document_names = map(lambda key: key.name, keys)

    # don't show directory in listing
    document_names = map(lambda name: name.replace('%s/' % self.gpg_email, ''),
      document_names)
    return document_names


  def delete(self, document_name, recipient=None):
    """ Deletes the given locked document. """
    recipient = recipient if not recipient == None else self.gpg_email
    key = s3.Key(self.bucket)
    key.key = '%s/%s' % (recipient, document_name)

    try:
      key.delete()
    except boto.exception.S3ResponseError:
      return False
    else:
      return True


  def release(self, document_name, recipient):
    """
    Releases the given document to the provided recipient. The recipient should
    be specified by an email address, and his/her public key should be available in
    the gpg keychain.
    """
    document_text = self.read(document_name)

    # release if we could read the given document
    if not document_text == None:
      self.store(document_name, document_text, recipient)
      return True

    return False


  def revoke(self, document_name, recipient):
    """
    Revokes access to the given document from the provided recipient. The
    recipient should be specified by an email address.
    """
    document_text = self.read(document_name)

    # revoke if we could read the given document
    if not document_text == None:
      self.delete(document_name, recipient)
      return True

    return False
