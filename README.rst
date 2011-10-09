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

From the top-level directory, issue: ::

  $ python setup.py install

To run the unit-tests, issue: ::

  $ python setup.py test


Documentation
=============

**The Flow Platform: Python Client Library** uses Sphinx to generate its API documentation.

To build local HTML documentation, issue the following command from the library's top-level directory: ::

  $ make html

The generated files will be placed in ``build/html``.

For more information on available options, issue: ::

  $ make help

.. _Sphinx: http://http://sphinx.pocoo.org/

Usage
=====

**Using the HTTP Client**

The ``flow.RestClient`` uses native python strings as its data interchange format.

All platform authentication is handled by the internals of the client.

Simply supply your application key and application secret to the ``flow.RestClient`` constructor.

In order to make API calls on behalf of an identity or application, provide the ID of the said resource
to the client's ``set_actor`` method.

All requests and responses can be logged to a file you specify. Provide the filename when invoking
``flow.RestClient.set_logger_file``.

To execute requests against the Flow API, invoke the client's ``http_*`` methods. ::

  import flow

  client = flow.RestClient(APPLICATION_KEY, APPLICATION_SECRET)
  client.set_actor(MY_IDENTITY_ID)
  client.set_logger_file('usage_example.out')
  client.set_logger_level(logging.DEBUG)

  response = client.http_get('/flow', qs={'limit': 10})

To take advantage of the library's features and its full domain model, use ``flow.JsonRestClient`` or ``flow.XmlRestClient``
as your transport mechanism.

These marshaling REST clients convert the raw response strings received from the Flow API into python-friendly
JSON or XML data (using the ``json`` and ``xml.dom`` modules, respectively). 

When using the CRUD methods on these clients, instances of the library's domain objects will be returned.

If at any point a HTTP request is unsuccessful, an exception will be raised. 

**Using the Flow Domain Model**

Each model present in the Flow Platform is represented by a class in the python client library.

Instances of these domain model classes follow an Active Record pattern.

  * Creation and Modification :: 
    
      #
      # the `save` method invokes a call to the platform which will remotely persist the object
      #

      my_coupons = flow.Flow(path = '/identity/jeffo/coupons', name = 'My Coupons').save()

      #
      # post-save, an id is assigned
      #

      assert(my_coupons.id is not None)

      my_coupons.description = 'A coupon flow that tracks the SmartSource RSS feed'

      #
      # an object that already has a Flow identifier will be updated when `save` is again invoked
      #

      my_coupons.save()

  * Retrieval ::

      #
      # specifiying an identifier will return the requested resource, if it exists
      #

      one_flow = flow.Flow.find(id = my_coupons.id) 

      assert(one_flow.id == my_coupons.id)

      #
      # specifiying non-identifiers will return all matching resources as a `flow.DomainObjectIterator`
      #

      many_flows = flow.Flow.find(name = 'My Coupons') # can specify one or many data members

      assert(many_flows.size() > 0)

      many_flows.size() # 1

      #
      # full-text search is also available via the find method, when using the `query` keyword argument
      #

      results = flow.Flow.find(query = 'coupon*')
      
      #
      # add `offset`, `limit`, `sort` and `order` modifiers to any `find` invokation
      #
      
      results = flow.Find.find(name = 'My Coupons', local = False, offset = 10, limit = 10)

  * Deletion ::

      my_coupons.delete()

      assert(my_coupons is None)

.. _ActiveRecord: http://martinfowler.com/eaaCatalog/activeRecord.html

Author / Maintainer
===================

Jeffrey Olchovy <`jeff@flow.net`_>

.. _jeff@flow.net: jeff@flow.net
