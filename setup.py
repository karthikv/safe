from setuptools import setup

with open('requirements.txt', 'r') as handle:
  requirements = handle.read().splitlines()

setup(name='safe',
      version='0.1',
      description='Manage sensitive files stored on S3 using GPG.',
      author='Karthik Viswanathan',
      author_email='karthik.ksv@gmail.com',
      packages=['safe'],
      scripts=['bin/safe'],
      install_requires=requirements,
      zip_safe=False)
