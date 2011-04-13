#!/usr/bin/env python

version = '0.1'

conf = {
  'name' : 'flow',
  'version' : version,
  'description' : 'Flow platform client library',
  'long_description' : 'Python client for the Flow platform.',
  'url': 'http://github.com/jeffreyolchovy/flow-py',
  'author' : 'jeff',
  'author_email' : 'jeff@flow.net',
  'maintainer' : 'jeff',
  'maintainer_email' : 'jeff@flow.net',
  'keywords': ['Flow'],
  'license': 'MIT',
  'packages': ['flow'],
  'test_suite': 'tests.client_test',
  'classifiers': [
    'Development Status :: 0',
    'Environment :: Console',
    'Intended Audience :: Developers',
    'License :: OSI Approved :: MIT License',
    'Operating System :: OS Independent',
    'Programming Language :: Python'],
}

try:
  from setuptools import setup
except ImportError:
  from distutils.core import setup
  
setup(**conf)
