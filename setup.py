#!/usr/bin/env python

version = '0.1.2'

conf = {
  'name' : 'flow',
  'version' : version,
  'description' : 'Flow platform client library',
  'long_description' : 'Python client for the Flow platform.',
  'url': 'http://github.com/jeffreyolchovy/flow-python-client',
  'author' : 'jeffreyolchovy',
  'author_email' : 'jeff@flow.net',
  'maintainer' : 'jeffreyolchovy',
  'maintainer_email' : 'jeff@flow.net',
  'py_modules': ['flow'],
  'keywords': ['Flow', 'PAAS'],
  'license': 'New-style BSD',
  'classifiers': [
    'Development Status :: 0',
    'Environment :: Console',
    'Intended Audience :: Developers',
    'License :: New-Style BSD',
    'Operating System :: OS Independent',
    'Programming Language :: Python'],

  'test_suite': 'tests'
}

try:
  from setuptools import setup
except ImportError:
  from distutils.core import setup
  
setup(**conf)
