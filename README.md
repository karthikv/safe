# Safe
`safe` keeps track of sensitive data in Amazon S3, PGP encrypting it for
security.

## Installation
To install, clone this repository and run:

```sh
$ python setup.py install
```

Do this **outside** of any virtual environment and you'll have the `safe`
command line tool installed on your system.

## Configure your environment
When you run `safe` for the first time, it'll ask for you three configuration
options: the email associated with your GPG key, your AWS access key for S3,
and your AWS secret key for S3. These are then saved in the `~/.saferc`
configuration file (encrypted with GPG, of course). If you ever need to change
these options or reconfigure, simply delete `~/.saferc` and run `safe` again.

## Commands
`safe ls`: Lists all documents in the safe.

`safe store [document_name]`: Store a document with the given name in the safe.
This will prompt you for the document text. Terminate the text with an EOF
character (ctrl + D).

`safe cat [document_name]`: Reads and outputs the document with the given name.

`safe rm [document_name]`: Removes a document with the given name.

`safe release [document_name] [recipient1] [recipient2]`: Release the document
with the given name to the target recipients. You must have their public GPG
keys in your keychain. At least one recipient is required.

`safe revoke [document_name] [recipient1] [recipient2] ...`: Revokes the
document with the given name from the target recipients. At least one recipient
is required.

`safe fetch [config_file]`: Fetches files from the safe according to the
specified configuration file. The configuration file should be in YAML with
the following format:

```yml
files:
  document-name: local/path/to/file
  other-document-name: path/to/where/document/will/be/downloaded
```

`files` is a hash map with keys that correspond to document names and values
that correspond to local file paths. `safe fetch` will download each document
and fetch it to the corresponding file path. This is a nice tool to manage
sensitive files, like `local_settings.py`, which should not be on GitHub.
