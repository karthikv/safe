import os
import gnupg
import boto
import json
import getpass
from boto.s3 import connection as s3


class Safe(object):
  SAFE_CONFIG_FILE = os.path.expanduser('~/.saferc')

  GPG_EMAIL_CONFIG_KEY = 'gpg_email'

  AWS_SAFES_CONFIG_KEY = 'aws_safes'
  AWS_ACCESS_CONFIG_KEY = 'aws_access_key'
  AWS_SECRET_ACCESS_CONFIG_KEY = 'aws_secret_access_key'
  AWS_BUCKET_NAME_CONFIG_KEY = 'aws_bucket_name_key'

  USE_GPG_AGENT_CONFIG_KEY = 'use_gpg_agent_key'
  ENCRYPTED_DATA_CONFIG_KEY = 'encrypted_config_key'

  CURRENT_SAFE_CONFIG_KEY = 'current_safe'

  def __init__(self):
    """ Creates a Safe that contains locked documents. """
    # set up GPG and S3 interfaces
    self.gpg = gnupg.GPG()
    self._fetch_config_options()
    self._establish_s3_connection()


  def _fetch_config_options(self):
    """
    Fetches the GPG email, AWS access key, and AWS secret key from the safe
    config file. If no config file exists, queries the user for input. Stores
    the user input in a new config file.
    """
    if os.path.isfile(self.SAFE_CONFIG_FILE):
      # config file exists; read in options
      handle = open(self.SAFE_CONFIG_FILE, 'r')
      config_contents = handle.read()
      handle.close()

      try:
        plaintext_config = json.loads(str(config_contents))
        self.use_agent = bool(plaintext_config[self.USE_GPG_AGENT_CONFIG_KEY])

        if self.use_agent:
          self.gpg = gnugp.GPG(use_agent=True)

        config = json.loads(str(self._decrypt(
          plaintext_config[self.ENCRYPTED_DATA_CONFIG_KEY])))

      except ValueError:
        raise Exception('Config file is invalid. If safe got updated recently,' +
          ' please delete your config file at ~/.saferc. Otherwise, ensure that' +
          ' GPG agent is running.')
      else:
        self.gpg_email = config[self.GPG_EMAIL_CONFIG_KEY]
        self.safes = config[self.AWS_SAFES_CONFIG_KEY]
        self.current_safe = config[self.CURRENT_SAFE_CONFIG_KEY]
    else:
      # no config file; ask for user input and remember it
      print "It seems like this is your first time using safe. Let's set it up, shall we?"

      self.gpg_email = raw_input('Enter your GPG key email: ')
      self.use_agent = self._ask_yes_no('Would you like to use your GPG Agent? (y/n): ')
      self.safes = {}
      self.current_safe = ""

      self._save_config_file()

      safe_name = raw_input('Enter a safe name: ')
      self.create(safe_name)


  def _ask_yes_no(self, question):
    """
    Asks the user for a YES or NO response. Returns True or False
    accordingly.
    """
    valid_resp = { 'yes': True,
              'y': True,
              'no': False,
              'n': False,
    }

    while True:
      resp = raw_input(question).lower()
      if resp in valid_resp:
        return valid_resp[resp]
      else:
        print "Please respond with 'yes' or 'no'."


  def _save_config_file(self):
    """ Encrypts and writes the settings to the config file. """
    config = {
      self.GPG_EMAIL_CONFIG_KEY: self.gpg_email,
      self.AWS_SAFES_CONFIG_KEY: self.safes,
      self.CURRENT_SAFE_CONFIG_KEY: self.current_safe,
    }

    encrypted_config = self._encrypt(json.dumps(config), self.gpg_email)

    config_contents = {
      self.USE_GPG_AGENT_CONFIG_KEY: self.use_agent,
      self.ENCRYPTED_DATA_CONFIG_KEY: str(encrypted_config),
    }

    # we're storing sensitive AWS keys, so encrypt them first
    with open(self.SAFE_CONFIG_FILE, 'w') as handle:
      handle.write(json.dumps(config_contents))


  def _establish_s3_connection(self):
    """ Establishes a connection with S3 using environment variables. """
    if len(self.safes) < 1:
      raise Exception('Please define at least one safe using \'safe create\'') 

    if not self.current_safe:
      raise Exception('Please set the safe you want to access using \'safe set\'')

    connection = s3.S3Connection(
        self.safes[self.current_safe][self.AWS_ACCESS_CONFIG_KEY],
        self.safes[self.current_safe][self.AWS_SECRET_ACCESS_CONFIG_KEY])
    self.bucket = connection.get_bucket(self.safes[self.current_safe]
        [self.AWS_BUCKET_NAME_CONFIG_KEY])


  def _encrypt(self, data, recipient):
    """ Encrypts data with the given GPG key. """
    if self.use_agent:
      encrypted_data = self.gpg.encrypt(data, recipient)
    else:
      if not hasattr(self, 'passphrase'):
        self.passphrase = getpass.getpass('Enter your GPG passphrase: ')
      encrypted_data = self.gpg.encrypt(data, recipient, passphrase=self.passphrase)

    return encrypted_data


  def _decrypt(self, data):
    """ Decrypts data with the given GPG key. """
    if self.use_agent:
      decrypted_text = str(self.gpg.decrypt(data))
    else:
      if not hasattr(self, 'passphrase'):
        self.passphrase = getpass.getpass('Enter your GPG passphrase: ')
      decrypted_text = str(self.gpg.decrypt(data, passphrase=self.passphrase))

    return decrypted_text

  def create(self, safe_name):
    """
    Allows the user to create a safe with the given name. Queries the user for
    the AWS access key, secret key and the bucket name. Saves these settings to
    the config file.
    """
    if safe_name in self.safes:
      raise Exception('The safe name [%s] already exists! Try another name ' +
          'or delete the existing safe.' % safe_name)
  
    aws_access_key = raw_input('Enter your AWS access key: ')
    aws_secret_access_key = raw_input('Enter your AWS private access key: ')
    aws_bucket_name = raw_input('Enter the AWS bucket name: ')

    self.safes[safe_name] = {
      self.AWS_ACCESS_CONFIG_KEY: aws_access_key,
      self.AWS_SECRET_ACCESS_CONFIG_KEY: aws_secret_access_key,
      self.AWS_BUCKET_NAME_CONFIG_KEY: aws_bucket_name,
    }

    self.current_safe = safe_name

    self._save_config_file()


  def delete(self, safe_name):
    """
    Removes all settings associated with a given safe name. These changes are
    reflected in the config file.
    """
    if safe_name not in self.safes:
      raise Exception('The safe name [%s] does not exist! Did you type it ' +
          'correctly?' % safe_name)

    del self.safes[safe_name]

    self._save_config_file()
  

  def show(self):
    """ Lists out all the safes that are currently being managed by safe. """
    return self.safes.keys()


  def set(self, safe_name):
    """ Sets the safe the user is currently working in. """
    if safe_name not in self.safes:
      raise Exception('The safe name [%s] does not exit.' % safe_name)

    self.current_safe = safe_name

    self._save_config_file()


  def current(self):
    """ Returns the safe name of the safe the user is currently working in. """
    return self.current_safe


  def store(self, document_name, document_text, recipient=None):
    """
    Encrypts the given text and stores it in a document with the provided name.
    Encrypts it for the given recipient. If recipient is not specified, encrypts
    it for the default gpg email.
    """
    # encrypt text
    document_text = document_text.strip()
    recipient = recipient if not recipient == None else self.gpg_email

    encrypted_text = self._encrypt(document_text, recipient)

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
      return self._decrypt(encrypted_text)


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
