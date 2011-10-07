========================================
The Flow Platform: Python Client Library
========================================

A python library for building applications that utilize the
Flow Platform.

**Features**

  * HTTP and XMPP clients
  * The Flow Platform domain model
  * Transparent conversions between XML, JSON and
    native python types

Installation
============
::
$ python setup.py install

To run the unit-tests, issue:

::
$ python setup.py test

Documentation
=============

The Flow Platform: Python Client Library uses Sphinx to generate its API documentation.

To build local HTML documentation issue the following command from
the library's top-level directory:

::
$ make html

The generated files will be placed in ``build/html``.

For more information on available options, issue:

::
$ make help

Usage
=====

**Instantiating a HTTP Client**

The ``flow.RestClient`` uses native python strings as its data interchange format.

All platform authentication is handled by the internals of the client.
Simply supply your application key and secret to the ``flow.RestClient`` constructor.
In order to make API calls on behalf of an identity or application, provide the ID of the said resource
to ``flow.RestClient``'s ``set_actor`` method.

All requests and responses can be logged to a file you specify. Provide the filename when invoking
``flow.RestClient.set_logger_file``.

To execute requests against the Flow API, invoke the client's ``http_*`` methods.

  ::
  import flow

  client = flow.RestClient(APPLICATION_KEY, APPLICATION_SECRET)
  client.set_actor(MY_IDENTITY_ID)
  client.set_logger_file('usage_example.out')
  client.set_logger_level(logging.DEBUG)

  response = client.http_get('/flow', qs={'limit': 10})

Author / Maintainer
===================

Jeffrey Olchovy <`jeff@flow.net`_>

.. _jeff@flow.net: jeff@flow.net
