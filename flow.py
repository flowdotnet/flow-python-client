"""Flow Platform Python Client Library

Copyright (c) 2010-2011, Flow Search Corporation

All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

  * Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.

  * Redistributions in binary form must reproduce the above
    copyright notice, this list of conditions and the following
    disclaimer in the documentation and/or other materials provided
    with the distribution.

  * Neither the name of the Flow Platform nor the names of its
    contributors may be used to endorse or promote products derived
    from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""

__author__    = 'Jeffrey Olchovy <jeff@flow.net>'
__version__   = '0.1.0'
__copyright__ = 'Copyright (c) 2010-2011 Flow Search Corporation' 
__license__   = 'New-style BSD'

import os, sys, logging
import httplib, urllib
import time, hashlib
import json

API_HOST = 'localhost'
API_PORT = 8080

FILE_SERVER_HOST = 'file.flow.net'
FILE_SERVER_PORT = 80

class RestClient(object):
  """A handle to the Flow Platform's RESTful API."""

  MIME_JSON = 'application/json'
  MIME_XML  = 'text/xml'

  DEFAULT_HEADERS = {
    'GET'     : { 'Accept' : MIME_JSON },
    'POST'    : { 'Accept' : MIME_JSON, 'Content-type' : MIME_JSON },
    'PUT'     : { 'Accept' : MIME_JSON, 'Content-type' : MIME_JSON },
    'DELETE'  : { 'Accept' : MIME_JSON }}

  def __init__(self, key, secret, actor=None):
    if actor is not None: self.actor = actor

    self.key = key
    self.secret = secret
    self.opts = dict([('headers', {}), ('params', {})])
    self.logger = logging.getLogger('flow.RestClient')
    self.set_logger_level(logging.DEBUG)

  def set_actor(self, actor):
    """Make requests on behalf of this identity / application."""
    self.actor = actor

  def set_opts(self, opts):
    """Global options applied to all requests.

    These options can be overidden at request-time.

    opts -- a dictionary of HTTP headers and query parameters

    """
    if 'headers' not in opts: opts['headers'] = {}
    if 'params' not in opts: opts['params'] = {}

    self.opts = opts

  def set_logger_level(self, level):
    self.logger.setLevel(level)

  def set_logger_file(self, filename):
    self.logger.addHandler(logging.FileHandler(filename))

  def _mk_creds(self):
    """Build necessary credential headers from instance attrs."""
    headers = {
        'X-Actor': self.actor,
        'X-Key': self.key,
        'X-Timestamp': self._mk_timestamp()}

    headers['X-Signature'] = self._mk_signature(headers)
    return headers

  def _mk_timestamp(self):
    """Milliseconds since the epoch, for signing requests."""
    return str(int(time.time() * 1000))

  def _mk_signature(self, creds):
    """Build the SHA1 hash of the credentials headers.
    
    creds -- the key-value pairs of the HTTP credentials headers
    
    """
    md = hashlib.sha1()

    for pair in sorted(creds.iteritems()):
      md.update(str(pair[0].lower()) + ':' + str(pair[1]))
    else:
      md.update(self.secret)

    return md.hexdigest()

  def _mk_opts(self, opts):
    """Merge given opts with global opts.
    
    opts -- dictionary of HTTP header and query paramter key-value pairs

    """
    if 'headers' not in opts: opts['headers'] = {}
    if 'params' not in opts: opts['params'] = {}

    opts['headers'].update(self.opts['headers'])
    opts['params'].update(self.opts['params'])

    return opts

  def _mk_headers(self, default, given):
    """Supplement given headers with:
    
    1. default headers
    2. credentials headers
    3. user-agent header (for tracking requests made from this lib)

    default -- the default key-value pairs for the given request method
    given -- key-value pairs given at request time

    """
    if given:
      headers = dict(default, **given)
    else:
      headers = default

    headers['User-Agent'] = 'flow-python-client_%s' % __version__
    return dict(headers, **self._mk_creds())

  def _mk_url(self, base, params):
    """Append encoded query parameters to the uri path.
    
    Positional arguments:
    base -- the base uri part path as a string, minus the hostname, e.g. /user
    params -- a key-value map of quer parameters
    
    """
    if params:
      return '%s?%s' % (base, urllib.urlencode(params))
    else:
      return base

  def _mk_request(self, url, method, data=None, opts={}):
    """Build a request's opts, url, and headers, and then execute it.
    
    Positional arguments:
    url -- API endpoint part path without url-encoded query parameters
    method -- HTTP method
    data -- data, as string, to be contained in request entity body
    opts -- key-value pairs of HTTP headers and query parameters

    """
    opts = self._mk_opts(opts)
    url = self._mk_url(url, opts['params'])
    headers = self._mk_headers(
        RestClient.DEFAULT_HEADERS[method], opts['headers'])

    return self.request(url, method, data, headers)

  def request(self, url, method, data=None, headers={}):
    """Execute HTTP request against the Flow Platform API.

    Returns the raw response string.

    All requests will be logged. See help(set_logger_handler).

    Positional arguments:
    url -- API endpoint with url encoded query paramters
    method -- HTTP method
    data -- data, as string,to be contained in request entity body
    headers -- HTTP headers

    """
    data = data.encode('utf-8') if data else None
    conn = httplib.HTTPConnection(API_HOST + ':' + str(API_PORT))
    conn.request(method, url, data, headers)
    response = conn.getresponse()
    response_str = response.read().decode('utf-8')
    self.logger.debug('\n'.join([
      '-- Begin REST Request --',
      'method> %s' % method,
      'url> %s' % url,
      'entity_body>\n%s' % data,
      'headers>\n%s' % headers,
      'response>\n%s' % response_str,
      '-- End REST Request --\n']))

    return response_str

  ### Raw data operations ###

  def http_get(self, url, opts={}):
    """Execute an HTTP GET request.

    Positional arguments:
    url -- API endpoint
    opts -- key-value pairs of HTTP headers and query parameters

    """
    return self._mk_request(url, 'GET', None, opts)

  def http_post(self, url, data, opts={}):
    """Execute an HTTP POST request.

    Positional arguments:
    url -- API endpoint
    data -- data, as string,to be contained in request entity body
    opts -- key-value pairs of HTTP headers and query parameters

    """
    return self._mk_request(url, 'POST', data, opts)

  def http_put(self, url, data, opts={}):
    """Execute an HTTP PUT request.

    Positional arguments:
    url -- API endpoint
    data -- data, as string,to be contained in request entity body
    opts -- key-value pairs of HTTP headers and query parameters

    """
    return self._mk_request(url, 'PUT', data, opts)

  def http_delete(self, url, data=None, opts={}):
    """Execute an HTTP DELETE request.

    Positional arguments:
    url -- API endpoint
    data -- data, as string,to be contained in request entity body
    opts -- key-value pairs of HTTP headers and query parameters

    """
    return self._mk_request(url, 'DELETE', data, opts)

class MarshalingRestClient(RestClient):
  """A handle to the Flow Platform RESTful API that can serialize
  and deserialize objects for easy CRUD and lookup operations
  on the Flow Platform's domain objects."""
  def __init__(self, marshaler, key, secret, actor=None, is_active_client=True):
    if is_active_client: DomainObject.active_client = self

    self.marshaler = marshaler
    super(MarshalingRestClient, self).__init__(key, secret, actor)

  def response_ok(self, response):
    """Did the request execute successfully?"""
    raise NotImplemented('Implementation of this method required.')

  def response_body(self, response):
    """The return values of an HTTP request, without response metadata."""
    raise NotImplemented('Implementation of this method required.')

  def marshal(self, obj):
    """Serialize an object into a raw data string."""
    return self.marshaler.dumps(obj)

  def unmarshal(self, data, obj=None):
    """Deserialize a raw data string into an object."""
    return self.marshaler.loads(data, obj)

  def create(self, cls, uri, data):
    """Create an instance of a domain object from an HTTP POST request."""
    response = self.http_post(uri, data)
    return cls(**self.response_body(response))

  def update(self, cls, uri, data):
    """Return an instance of a domain object from an HTTP PUT request."""
    response = self.http_put(uri, data)
    return cls(**self.response_body(response))

  def delete(self, cls, uri, data=None):
    """Remove a domain object via an HTTP DELETE request."""
    response = self.http_delete(uri, data)
    return self.response_ok(response)

  def find_one(self, cls, uri):
    """Return a single instance of a domain object via an HTTP GET request."""
    response = self.http_get(uri)
    return cls(**self.response_body(response))

  def find_many(self, cls, uri, data=None, **kargs):
    """Return a list of instances of a single type of domain object that satisfies..

    """
    opts = {'params': {'criteria': self.marshal(data)}} if data else {'params': {}}
    opts['params'].update(kargs)
    results = self.response_body(self.http_get(uri, opts))

    return [cls(**result) for result in results]

  def search(self, *cls, **kargs):
    """Return a list of instances of domain objects that satisfies the given full-text search query.

    """
    types = ','.join([c.type_hint() for c in list(cls)])
    opts = {'params': kargs}
    opts['params'].update({'type': types})
    results = self.response_body(self.http_get('/search', opts))['results']

    return [DomainObjectFactory.get_instance(result['type'], **result['value']) \
        for result in results['value']]

class JsonRestClient(MarshalingRestClient):
  """A marshaling REST Client that uses JSON as its data interchange format."""
  def __init__(self, key, secret, actor=None):
    super(JsonRestClient, self).__init__(JsonMarshaler(), key, secret, actor)
    self.set_opts({'params': {'hints': 1}})

  def _parse_unicode(self, data):
    if isinstance(data, unicode):
      return str(data)
    elif isinstance(data, dict):
      return dict(map(self._parse_unicode, data.iteritems()))
    elif isinstance(data, (list, tuple, set, frozenset)):
      return type(data)(map(self._parse_unicode, data))
    else:
      return data

  def _parse_response(self, raw_response):
    try:
      return self._parse_unicode(json.loads(raw_response))

    except ValueError as e:
      raise UnparsableResponseError(raw_response, 'JSON response data could not be parsed')

  def response_ok(self, response):
    if isinstance(response, basestring):
      response = self._parse_response(response)

    return ('head' in response
      and 'body' in response
      and 'ok' in response['head']
      and response['head']['ok'])

  def response_body(self, response):
    if isinstance(response, basestring):
      response = self._parse_response(response)

    if self.response_ok(response):
      return response['body']
    else:
      raise JsonResponseError(response, 'Response status not \'ok\'')

class XmlRestClient(MarshalingRestClient):
  """A marshaling REST Client that uses XML as its data interchange format."""
  def __init__(self, key, secret, actor=None):
    super(XmlRestClient, self).__init__(XmlMarshaler(), key, secret, actor)
    self.set_opts({
        'params': {'hints': 1},
        'headers': {
          'Content-type': RestClient.MIME_XML,
          'Accept': RestClient.MIME_XML}})

  def _parse_response(self, raw_response):
    raise UnparsableResponseError(raw_response, 'XML response data could not be parsed')

  def response_ok(self, response):
    if isinstance(response, basestring):
      response = self._parse_response(response)

    raise XmlResponseError(response, 'Response status not \'ok\'')

  def response_body(self, response):
    if isinstance(response, basestring):
      response = self._parse_response(response)

    if self.response_ok(response):
      return response
    else:
      raise XmlResponseError(response, 'Response status not \'ok\'')

class UnparsableResponseError(Exception):
  def __init__(self, raw_response, message=None):
    self.response = raw_response
    self.message = message if message else ''

class ParsableResponseError(Exception):
  def __init__(self, response, description=None):
    self.response = response
    self.description = description if description else 'No description available'

  def messages(self):
    raise NotImplemented('Implementation of this method required.')

  def errors(self):
    raise NotImplemented('Implementation of this method required.')

  def status(self):
    raise NotImplemented('Implementation of this method required.')

class JsonResponseError(ParsableResponseError):
  def messages(self):
    pass

  def errors(self):
    pass

  def status(self):
    pass

class XmlResponseError(ParsableResponseError):
  def messages(self):
    pass

  def errors(self):
    pass

  def status(self):
    pass

class Marshaler(object):
  def dumps(self, obj):
    raise NotImplemented('Implementation of this method required.')

  def loads(self, obj, data):
    raise NotImplemented('Implementation of this method required.')

class JsonMarshaler(Marshaler):
  def _mk_field(self, k, v):
    if isinstance(v, dict):
      return (k, v)
    elif isinstance(v, list):
      return (k, {'type': 'list', 'value': v})
    elif isinstance(v, bool):
      return (k, {'type': 'boolean', 'value': v})
    elif isinstance(v, int):
      return (k, {'type': 'integer', 'value': v})
    elif isinstance(v, float):
      return (k, {'type': 'float', 'value': v})
    elif(isinstance(v, basestring)):
      return (k, {'type': 'string', 'value': v})
    else:
      return (k, None)

  def dumps(self, obj):
    if isinstance(obj, DomainObject):
      kv_pairs = obj.get_members().iteritems()
    elif isinstance(obj, dict):
      kv_pairs = obj.iteritems()
    else:
      raise ValueError('Cannot marshal object %s' % obj)

    json_dict = dict([self._mk_field(k, v) for k, v in kv_pairs])

    return json.dumps(json_dict)

  def loads(self, data, obj=None):
    if isinstance(obj, DomainObject):
      obj.set_members(**json.loads(data))
    else:
      obj = json.loads(data)

    return obj

class XmlMarshaler(Marshaler):
  def _mk_elem(self, k, v):
    """
    dom = dom.getDocumentImplementation()
    if isinstance(v, dict):
      parent = document.createElement(k)
      for k, v in dict.iteritems():
        child = self._mk_elem(k, v)
        parent.appendChild(child)
    elif isinstance(v, list):
      parent = document.createElement(k)
      for v in list:
        child = self._mk_elem('item', v)
        parent.appendChild(child)
    elif:
      parent = document.createElement(k)
    elif isinstance(v, bool):
      return (k, {'type': 'boolean', 'value': v})
    elif isinstance(v, int):
      return (k, {'type': 'integer', 'value': v})
    elif isinstance(v, float):
      return (k, {'type': 'float', 'value': v})
    elif(isinstance(v, basestring)):
      return (k, {'type': 'string', 'value': v})
    else:
      return (k, None)
    """
    pass

  def dumps(self, obj):
    """
    doc = xml.Document()
    """
    pass

class DomainObject(object):
  """A base abstract class for Flow Domain Objects."""
  active_client = None

  members = [
      'id',
      'creator',
      'creationDate',
      'lastEditDate']

  def __init__(self, **kargs):
    self.set_members(**kargs)

  def __getattr__(self, name):
    if name in self.__dict__:
      value = self.__dict__[name]

      if isinstance(value, dict) \
        and 'value' in value \
        and not isinstance(value['value'], dict):
        return value['value']
      else:
        return value
    elif name in self.__class__.members:
      return None
    else:
      raise AttributeError()

  def __setattr__(self, name, value):
    if name in self.__class__.members:
      self.__dict__[name] = value
    else:
      raise AttributeError()

  def __delattr__(self, name):
    if name in self.__class__.members:
      self.__dict__[name] = None
    else:
      raise AttributeError()

  def __eq__(self, other):
    return self.__class__ == other.__class__ \
        and self.get_uid() == other.get_uid()

  def __ne__(self, other):
    return not self.__eq__(other)

  def get_member(self, name):
    return self.__getattr__(name)

  def set_member(self, name, value):
    self.__setattr__(name, value)

  def get_members(self):
    """Return a key-value map of the domain object's data members."""
    return dict(filter(
        lambda x: x[1] is not None,
        [(k, self.__getattr__(k)) for k in self.__class__.members]))

  def set_members(self, **kargs):
    """Set the data members of the domain object to the given key-value pairs."""
    for k, v in kargs.items():
      if k in self.__class__.members:
        self.__setattr__(k, v)

  def get_uid(self):
    """Return the unique identifier for this domain object."""
    id = self.__getattr__('id')

    if isinstance(id, basestring):
      return id
    elif isinstance(id, dict) and 'value' in id:
      return id['value']
    else:
      return None

  def save(self, client=None):
    """Persist an object in the Flow Platform.

    Positional arguments:
    client -- (optional) marshaling client, defaults to current active client

    """
    active_client = self.__class__.active_client if not client else client

    if not active_client:
      raise ValueError('An active REST client is required')

    uid = self.get_uid()
    id = self.id

    # remove id member before marshaling object to avoid
    # '\'id\' is not a member of this resource' messages
    del self.id

    data = active_client.marshal(self)
    self.id = id 

    if not uid:
      uri = self.__class__.class_bound_path()
      return active_client.create(self.__class__, uri, data)
    else:
      uri = self.__class__.instance_bound_path(uid)
      return active_client.update(self.__class__, uri, data)

  def update(self, client=None, member=None):
    """Persist an object or one of its members in the Flow Platform.

    Positional arguments:
    client -- (optional) marshaling client, defaults to current active client
    member -- (optional) name of data member to be updated

    """
    active_client = self.__class__.active_client if not client else client

    if not active_client:
      raise ValueError('An active REST client is required')

    uid = self.get_uid()
    
    if not uid:
      raise Exception('Cannot update without \'id\' member set')

    if not member:
      return self.save(active_client)
    else:
      uri = self.__class__.instance_bound_path(uid) + '/' + member
      data = active_client.marshal(self)
      return active_client.update(self.__class__, uri, data)

  def delete(self, client=active_client, member=None):
    """Remove an object or one of its members from the Flow Platform.

    Positional arguments:
    client -- (optional) marshaling client, defaults to current active client
    member -- (optional) name of data member to be deleted

    """
    active_client = self.__class__.active_client if not client else client

    if not active_client:
      raise ValueError('An active REST client is required')

    uid = self.get_uid()

    if not uid:
      raise Exception('Cannot delete without \'id\' member set')

    if not member:
      uri = self.__class__.instance_bound_path(uid)
      return active_client.delete(self.__class__, uri)
    else:
      uri = self.__class__.instance_bound_path(uid) + '/' + member
      data = active_client.marshal(self)
      return active_client.delete(self.__class__, uri, data)

  @classmethod
  def type_hint(cls):
    """The common string name of the domain object."""
    return cls.__name__.lower()

  @classmethod
  def class_bound_path(cls):
    """The uri part path that reflects the entire class of this type."""
    return '/' + cls.type_hint()

  @classmethod
  def instance_bound_path(cls, id):
    """The uri part path that reflects a single instance of this type."""
    return '/'.join([cls.class_bound_path(), id]) 

  @classmethod
  def context_bound_path(cls, context=None):
    """The uri part path that reflects a subset of class instances bounded by some specified context."""
    if not context:
      return cls.class_bound_path()
    else:
      return '/'.join([cls.class_bound_path(), context])

  @classmethod
  def find(cls, client=None, **kargs):
    """Find instances of this class in the Flow Platform.
    
    Positional arguments:
    client -- (optional) marshaling client, defaults to current active client
    kargs -- one of query or filter, can set all or none of offset, limit, sort, order

    """
    active_client = cls.active_client if not client else client

    if not active_client:
      raise ValueError('An active REST client is required')

    if 'id' in kargs:
      uri = cls.instance_bound_path(kargs.pop('id'))
      return active_client.find_one(cls, uri)
    else:
      if 'bucketId' in kargs:
        uri = cls.context_bound_path(kargs.pop('bucketId'))
      else:
        uri = cls.class_bound_path()

      opts = dict([(opt, kargs.pop(opt)) for opt in \
          filter(lambda x: x in kargs, ['query', 'filter', 'offset', 'limit', 'sort', 'order'])])

      return active_client.find_many(cls, uri, kargs, **opts)

class Application(DomainObject):
  """A user generated application comprised of a template and a hierarchy of buckets."""
  members = DomainObject.members + [
      'name',
      'displayName',
      'description',
      'email',
      'url',
      'icon',
      'isDiscoverable',
      'isInviteOnly',
      'applicationTemplate',
      'permissions']

  def __init__(self, **kargs):
    super(Application, self).__init__(**kargs)

class Bucket(DomainObject):
  """A container for drops."""
  members = DomainObject.members + [
      'name',
      'description',
      'path',
      'filter',
      'location',
      'local',
      'template',
      'icon',
      'permissions',
      'dropPermissions']

  def __init__(self, **kargs):
    super(Bucket, self).__init__(**kargs)

class Comment(DomainObject):
  """A user generated comment around a drop or bucket."""
  members = DomainObject.members + [
      'title',
      'description',
      'text',
      'bucketId',
      'dropId',
      'parentId',
      'topParentId']

  def __init__(self, **kargs):
    super(Comment, self).__init__(**kargs)

class Drop(DomainObject):
  """An atomic piece of system data with map-like behavior."""
  members = DomainObject.members + [
      'bucketId',
      'path',
      'elems']

  def __init__(self, **kargs):
    super(Drop, self).__init__(**kargs)

  def get_uid(self):
    bucket_id = self.__getattr__('bucketId')
    id = self.__getattr__('id')

    if isinstance(bucket_id, basestring):
      bucket_id = bucket_id
    elif isinstance(bucket_id, dict) and 'value' in bucket_id:
      bucket_id = bucket_id['value']
    else:
      bucket_id = None

    if isinstance(id, basestring):
      id = id
    elif isinstance(id, dict) and 'value' in id:
      id = id['value']
    else:
      id = None

    if not bucket_id or not id:
      return None
    else:
      return '%s/%s' % (bucket_id, id)

class File(DomainObject):
  """A reference to file that is stored on 'http://file.flow.net'."""
  members = DomainObject.members + [
      'name',
      'mimeType',
      'contents']

  def __init__(self, **kargs):
    super(File, self).__init__(**kargs)

class Group(DomainObject):
  """A collection of identities that can act as a single persona."""
  members = DomainObject.members + [
      'name',
      'displayName',
      'identities',
      'permissions',
      'identityPermissions']

  def __init__(self, **kargs):
    super(Group, self).__init__(**kargs)

class Identity(DomainObject):
  """A user's persona."""
  members = DomainObject.members + [
      'firstName',
      'lastName',
      'alias',
      'avatar',
      'groupIds',
      'userId',
      'appIds',
      'permissions']

  def __init__(self, **kargs):
    super(Identity, self).__init__(**kargs)

class Track(DomainObject):
  """Data pipeline to connect one flow to another."""
  members = DomainObject.members + [
      'from',
      'to',
      'filterString',
      'transformFunction',
      'permissions']

  def __init__(self, **kargs):
    super(Track, self).__init__(**kargs)

class User(DomainObject):
  """A system user and a container for identities."""
  members = DomainObject.members + [
      'email',
      'password',
      'permissions']

  def __init__(self, **kargs):
    super(User, self).__init__(**kargs)

class DomainObjectFactory(object):
  """Factory class to instantiate domain objects based upon their string type-hints."""
  @staticmethod
  def get_instance(type_hint, **kargs):
    """Return an instance of a class by a given type-hint.

    Keyword arguments should be the key value mapping of 
    members to be set for the instance to be returned.

    >>> DomainObjectFactory().get_instance('user', email='alice@example.com')

    """
    if type_hint == 'application':
      return Application(**kargs)
    elif type_hint == 'bucket':
      return Bucket(**kargs)
    elif type_hint == 'comment':
      return Comment(**kargs)
    elif type_hint == 'drop':
      return Drop(**kargs)
    elif type_hint == 'file':
      return File(**kargs)
    elif type_hint == 'group':
      return Group(**kargs)
    elif type_hint == 'identity':
      return Identity(**kargs)
    elif type_hint == 'track':
      return Track(**kargs)
    elif type_hint == 'user':
      return User(**kargs)
    else:
      raise ValueError('Unknown type-hint \'%s\' supplied for instantiation' % type_hint)

if __name__ == '__main__':
  KEY     = sys.argv[1]
  SECRET  = sys.argv[2]
  ACTOR   = '000000000000000000000001'

  json_client = JsonRestClient(KEY, SECRET, ACTOR)
  json_client.set_logger_file('client.out')

  app_a = Application(
      name='lion_king',
      email='simba@priderock.org',
      description='the lion king').save()

  app_b = Application(
      name='hakuna_matata',
      email='simba@priderock.org',
      description='songs from the lion king').save()

  apps = Application.find(name='lion_king')
  print app_a in apps
  print app_b in apps
  print '-'.join(['' for x in range(0, 20)])

  apps = Application.find(email='simba@priderock.org')
  print app_a in apps
  print app_b in apps
  print '-'.join(['' for x in range(0, 20)])

  apps = Application.find(query='lion', limit=2)
  print app_a in apps
  print app_b in apps
  print '-'.join(['' for x in range(0, 20)])

  app_a.url = 'http://lionking.priderock.org'
  app_a.save()

  apps = json_client.search(Application, Bucket, query='lion', limit=2)

  for app in apps:
    print app.get_members()

  app_a.delete()
  app_b.delete()
