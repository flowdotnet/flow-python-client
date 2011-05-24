#!/usr/bin/env python

version = '0.1.0'

conf = {
  'name' : 'flow',
  'version' : version,
  'description' : 'Flow platform client library',
  'long_description' : 'Python client for the Flow platform.',
  'url': 'http://github.com/jeffreyolchovy/flow-py',
  'author' : 'jeffreyolchovy',
  'author_email' : 'jeff@flow.net',
  'maintainer' : 'jeffreyolchovy',
  'maintainer_email' : 'jeff@flow.net',
  'py_modules': ['flow'],
  'keywords': ['Flow'],
  'license': 'New-style BSD',
  'classifiers': [
    'Development Status :: 0',
    'Environment :: Console',
    'Intended Audience :: Developers',
    'License :: New-Style BSD',
    'Operating System :: OS Independent',
    'Programming Language :: Python'],
}

try:
  from setuptools import setup
except ImportError:
  from distutils.core import setup
  
setup(**conf)
