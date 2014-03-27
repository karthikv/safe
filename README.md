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
You'll need to define two variables in your shell environment to run `safe`:

- `AWS_ACCESS_KEY`: your AWS access key for S3
- `AWS_SECRET_ACCESS_KEY`: your AWS secret key for S3

To simplify this, I've created an `env.sh` file with the following contents:

```sh
export AWS_ACCESS_KEY=[your_aws_access_key]
export AWS_SECRET_ACCESS_KEY=[your_aws_secret_key]
```

I simply run `source env.sh` before running safe commands.

Alternatively, you could put those lines in your `~/.bash_profile` to make them
permanent.

## Commands
`safe ls`: Lists all documents in the safe.

`safe store [document_name]`: Store a document with the given name in the safe.
This will prompt you for the document text. Terminate the text with an EOF
character (ctrl + D).

`safe cat [document_name]`: Reads and outputs the document with the given name.

`safe rm [document_name]`: Removes a document with the given name.

`safe release [document_name] [recipient]`: Release the document with the given
name to the target recipient. You must have their public GPG key in your
keychain.

`safe revoke [document_name] [recipient]`: Revokes the document with the given
name to the target recipient. You must have their public GPG key in your
keychain.

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
