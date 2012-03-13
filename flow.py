"""Flow Platform: Python Client Library

Copyright (c) 2010-2012 Flow Search Corp.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

__author__    = 'Jeffrey Olchovy <jeff@flow.net>'
__version__   = '0.1.1'
__copyright__ = 'Copyright (c) 2010-2012 Flow Search Corp.' 
__license__   = 'Apache License, Version 2.0'

import __builtin__
import os, sys
import logging
import httplib, urllib
import hashlib
import datetime, time
import json, xml.dom.minidom
import re

API_HOST = 'api.flow.net'
API_PORT = 80

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
    """
    **Args:**
      key (str): Application key
      secret (str): Application secret
     
    **Keyword Args:**
      actor (str): ID of Identity or Application on whose behalf calls will be made

    **Returns:**
      RestClient

    """
    if actor is not None: self.actor = actor

    self.key = key
    self.secret = secret
    self.opts = dict([('headers', {}), ('qs', {})])
    self.logger = logging.getLogger('flow.RestClient')

  def set_actor(self, actor):
    """Make requests on behalf of this identity / application."""
    self.actor = actor

  def set_opts(self, opts):
    """Global options applied to all requests.

    .. note::
      These options can be overidden per request.

      >>> rest_client.http_get('/user', 'GET', {'hints': 0})

    **Args:**
      opts (dict): HTTP headers and query parameters.

    **Returns:**
      void

    """
    if 'headers' not in opts:
      opts['headers'] = {}

    if 'qs' not in opts:
      opts['qs'] = {}

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
    
    **Args:**
      creds (dict): Key-value pairs of the HTTP credentials headers

    **Returns:**
      str -- value of request signature
    
    """
    md = hashlib.sha1()

    for pair in sorted(creds.iteritems()):
      md.update(str(pair[0].lower()) + ':' + str(pair[1]))
    else:
      md.update(self.secret)

    return md.hexdigest()

  def _mk_opts(self, opts):
    """Merge given opts with global opts.
    
    **Args:**
      opts (dict): HTTP header and query paramter key-value pairs

    **Returns:**
      dict

    """
    if 'headers' not in opts:
      opts['headers'] = {}

    if 'qs' not in opts:
      opts['qs'] = {}

    opts['headers'].update(self.opts['headers'])
    opts['qs'].update(self.opts['qs'])

    return opts

  def _mk_headers(self, default, given):
    """Supplement a request's given headers with:
    
      1. default headers
      2. credentials headers
      3. user-agent header (used for tracking HTTP requests made from this library)

    **Args:**
      default (dict): The default key-value pairs for the given request method
      given (dict): The key-value pairs given at request time

    **Returns:**
      dict

    """
    if given:
      headers = dict(default, **given)
    else:
      headers = default

    headers['User-Agent'] = 'flow-python-client_%s' % __version__
    return dict(headers, **self._mk_creds())

  def _mk_uri(self, uri, qs_params):
    """Append encoded query parameters to the uri path.
    
    **Args:**
      base (str): The base uri part path as a string, minus the hostname, e.g. /user
      qs_params (dict): A key-value map of query parameters

    **Returns:**
      str
    
    """
    parts = uri.split('?')
    base = parts[0]
    qs = parts[1] if len(parts) > 1 else None

    if qs and qs_params:
      qs = '%s&%s' % (qs, urllib.urlencode(qs_params))
      return '%s?%s' % (base, qs)

    if qs_params:
      return '%s?%s' % (base, urllib.urlencode(qs_params))

    else:
      return uri

  def _mk_request(self, uri, method, data=None, opts=None):
    """Build a request's opts, uri, and headers, and then execute it.
    
    **Args:**
      uri (str): an API endpoint part path with or without url-encoded query parameters
      method (str): HTTP method
      data (str): data, as a string, to be placed in the request's entity body
      opts (dict): key-value pairs of HTTP headers and query parameters

    **Returns:**
      str

    """
    opts = self._mk_opts(opts if opts else {})
    uri = self._mk_uri(uri, opts['qs'])
    headers = self._mk_headers(RestClient.DEFAULT_HEADERS[method], opts['headers'])

    return self.request(uri, method, data, headers)

  def request(self, uri, method, data=None, headers=None):
    """Execute HTTP request against the Flow Platform API.

    .. note::
      All requests will be logged. See help(set_logger_handler).

    **Args:**
      uri (str): API endpoint with uri encoded query paramters
      method (str): HTTP method

    **Keyword Args:**
      data (str): Request entity body
      headers (dict): HTTP headers

    """
    data = data.encode('utf-8') if data else None
    headers = headers if headers else {}
    conn = httplib.HTTPConnection(API_HOST + ':' + str(API_PORT))
    conn.request(method, uri, data, headers)
    response = conn.getresponse()
    response_str = response.read().decode('utf-8')
    self.logger.debug('\n'.join([
      '-- Begin REST Request --',
      'method> %s' % method,
      'uri> %s' % uri,
      'entity_body>\n%s' % data,
      'headers>\n%s' % headers,
      'response>\n%s' % response_str,
      '-- End REST Request --\n']))

    return response_str

  def http_get(self, uri, qs=None, headers=None):
    """Execute an HTTP GET request.

    **Args:**
      uri (str): API endpoint

    **Keyword Args:**
      opts (dict): Key-value pairs of HTTP headers and query parameters

    """
    return self._mk_request(uri, 'GET', None, {'qs': qs if qs else {}, 'headers': headers if headers else {}})

  def http_post(self, uri, data, qs=None, headers=None):
    """Execute an HTTP POST request.

    **Args:**
      uri (str): API endpoint
      data (str): Request entity body

    **Keyword Args:**
      opts (dict): Key-value pairs of HTTP headers and query parameters

    """
    return self._mk_request(uri, 'POST', data, {'qs': qs if qs else {}, 'headers': headers if headers else {}})

  def http_put(self, uri, data, qs=None, headers=None):
    """Execute an HTTP PUT request.

    **Args:**
      uri (str): API endpoint
      data (str): Request entity body

    **Keyword Args:**
      opts (dict): Key-value pairs of HTTP headers and query parameters

    """
    return self._mk_request(uri, 'PUT', data, {'qs': qs if qs else {}, 'headers': headers if headers else {}})

  def http_delete(self, uri, data=None, qs=None, headers=None):
    """Execute an HTTP DELETE request.

    **Args:**
      uri (str): API endpoint
      data (str): Request entity body

    **Keyword Args:**
      opts (dict): Key-value pairs of HTTP headers and query parameters

    """
    return self._mk_request(uri, 'DELETE', data, {'qs': qs if qs else {}, 'headers': headers if headers else {}})

class MarshalingRestClient(RestClient):
  """A handle to the Flow Platform RESTful API that can serialize
  and deserialize objects for easy CRUD and lookup operations
  on Flow Platform domain objects."""

  def __init__(self, marshaler, key, secret, actor=None, is_active_client=True):
    if is_active_client: DomainObject.active_client = self

    self.marshaler = marshaler
    super(MarshalingRestClient, self).__init__(key, secret, actor)

  def response_ok(self, response):
    """Did the request execute successfully?"""
    raise NotImplemented('Implementation of this method required.')

  def response_body(self, response):
    """The return value of an HTTP request, without response metadata."""
    raise NotImplemented('Implementation of this method required.')

  def marshal(self, obj):
    """Coerce an object into the marshaler's type kind."""
    return self.marshaler.dump(obj)

  def marshals(self, obj):
    """Serialize an object into a string representation of the marsheler's type."""
    return self.marshaler.dumps(obj)

  def unmarshal(self, data, type=None):
    """Coerce a marshaler's type kind into an object."""
    return self.marshaler.load(data, type)

  def unmarshals(self, data, type=None):
    """Deserialize a raw data string into an object."""
    return self.marshaler.loads(data, type)

  def create(self, cls, uri, data):
    """Create an instance of a domain object from an HTTP POST request."""
    response = self.http_post(uri, data)
    return cls(**Marshaler.kargify(self.response_body(response)))

  def update(self, cls, uri, data):
    """Return an instance of a domain object from an HTTP PUT request."""
    response = self.http_put(uri, data)
    return cls(**Marshaler.kargify(self.response_body(response)))

  def delete(self, cls, uri, data=None):
    """Remove a domain object via an HTTP DELETE request."""
    response = self.http_delete(uri, data)
    return self.response_ok(response)

  def find_one(self, cls, uri):
    """Return a single instance of a domain object via an HTTP GET request."""
    response = self.http_get(uri)
    return cls(**Marshaler.kargify(self.response_body(response)))

  def find_many(self, cls, uri, data=None, **kargs):
    """Return a list of instances of a single type of domain object that satisfies the given criteria."""
    qs = {'criteria': self.marshals(data)} if data else {}
    qs.update(kargs)
    return self.response_body(self.http_get(uri, qs=qs))

  def search(self, *cls, **kargs):
    """Return a list of instances of domain objects that satisfy the given full-text search query."""
    types = ','.join([c.type_hint() for c in list(cls)])
    qs = kargs
    qs.update({'type': types})
    results = self.response_body(self.http_get('/search', qs=qs))
    return results

class JsonRestClient(MarshalingRestClient):
  """A marshaling REST Client that uses JSON as its data interchange format."""

  def __init__(self, key, secret, actor=None):
    super(JsonRestClient, self).__init__(JsonMarshaler(), key, secret, actor)
    self.logger = logging.getLogger('flow.JsonRestClient')
    self.set_opts({
        'qs': {'hints': 1},
        'headers': {'Accept': RestClient.MIME_JSON}})

  def _parse_response(self, raw_response):
    try:
      return self.marshaler.loads(raw_response, 'map')

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

  def find_many(self, cls, uri, data=None, **kargs): 
    results = super(JsonRestClient, self).find_many(cls, uri, data, **kargs)
    return DomainObjectIterator([cls(**Marshaler.kargify(result)) for result in results])

  def http_post(self, uri, data, qs=None, headers=None):
    headers = headers if headers else {}
    headers['Content-type'] = RestClient.MIME_JSON
    return super(JsonRestClient, self).http_post(uri, data, qs, headers)

  def http_put(self, uri, data, qs=None, headers=None):
    headers = headers if headers else {}
    headers['Content-type'] = RestClient.MIME_JSON
    return super(JsonRestClient, self).http_put(uri, data, qs, headers)

  def http_delete(self, uri, data=None, qs=None, headers=None):
    if not headers: headers = {}
    if data: headers['Content-type'] = RestClient.MIME_JSON
    return super(JsonRestClient, self).http_delete(uri, data, qs, headers) 

class XmlRestClient(MarshalingRestClient):
  """A marshaling REST Client that uses XML as its data interchange format."""

  def __init__(self, key, secret, actor=None):
    super(XmlRestClient, self).__init__(XmlMarshaler(), key, secret, actor)
    self.logger = logging.getLogger('flow.XmlRestClient')
    self.set_opts({
        'qs': {'hints': 1},
        'headers': {'Accept': RestClient.MIME_XML}})

  def _parse_response(self, raw_response):
    try:
      return self.marshaler.loads(raw_response, 'map')
    except Exception as e:
      raise UnparsableResponseError(raw_response, 'XML response data could not be parsed')

  def response_ok(self, response):
    if isinstance(response, basestring):
      response = self._parse_response(response)

    return ('head' in response
        and 'body' in response
        and 'ok' in response['head']
        and response['head']['ok'] == 'true')

  def response_body(self, response):
    if isinstance(response, basestring):
      response = self._parse_response(response)

    if self.response_ok(response):
      return response['body']
    else:
      raise XmlResponseError(response, 'Response status not \'ok\'')

  def find_many(self, cls, uri, data=None, **kargs): 
    response_body = super(XmlRestClient, self).find_many(cls, uri, data, **kargs)
    result = response_body['results']['result']

    if isinstance(result, list):
      return DomainObjectIterator(result)
    else:
      return DomainObjectIterator([result])

  def http_post(self, uri, data, qs=None, headers=None):
    headers = headers if headers else {}
    headers['Content-type'] = RestClient.MIME_XML
    return super(XmlRestClient, self).http_post(uri, data, qs, headers) 

  def http_put(self, uri, data, qs=None, headers=None):
    headers = headers if headers else {}
    headers['Content-type'] = RestClient.MIME_XML
    return super(XmlRestClient, self).http_put(uri, data, qs, headers) 

  def http_delete(self, uri, data=None, qs=None, headers=None):
    if not headers: headers = {}
    if data: headers['Content-type'] = RestClient.MIME_XML
    return super(XmlRestClient, self).http_delete(uri, data, qs, headers) 

class UnparsableResponseError(RuntimeError):
  def __init__(self, raw_response, value=None):
    self.response = raw_response
    self.value = value if value else ''

class ParsableResponseError(RuntimeError):
  def __init__(self, response, description=None):
    self.response = response
    self.description = description if description else 'No description available'

  def messages(self):
    raise NotImplemented('Implementation of this method required.')

  def errors(self):
    raise NotImplemented('Implementation of this method required.')

  def status(self):
    return int(self.response['head']['status'])

class JsonResponseError(ParsableResponseError):
  def messages(self):
    return [message[1] for message in self.response['head']['messages']]

  def errors(self):
    return [error[1] for error in self.response['head']['errors']]

class XmlResponseError(ParsableResponseError):
  def messages(self):
    return self.response['head']['messages']['message'] 

  def errors(self):
    return self.response['head']['errors']['error']

class Marshaler(object):
  @staticmethod
  def kargify(kargs, encoding='ascii'):
    return dict([(k.encode(encoding), v) for k, v in kargs.iteritems()])

  def dump(self, obj):
    raise NotImplemented('Implementation of this method required.')

  def dumps(self, obj):
    raise NotImplemented('Implementation of this method required.')

  def load(self, data, type=None):
    raise NotImplemented('Implementation of this method required.')

  def loads(self, data, type=None):
    raise NotImplemented('Implementation of this method required.')

class JsonMarshaler(Marshaler):
  def dump(self, obj):
    is_labeled = lambda x: isinstance(x, tuple) and isinstance(x[0], basestring)
    is_typed = lambda x: isinstance(x, dict) and 'type' in x and 'value' in x

    if is_labeled(obj) and is_typed(obj[1]):
      return dict([(obj[0], obj[1])])
    elif is_typed(obj):
      return obj
    elif isinstance(obj, DomainObject):
      return dict([(k, self.dump(v)) for k, v in obj.get_members().iteritems()])
    elif isinstance(obj, dict):
      return {'type': 'map', 'value': dict([(k, self.dump(v) if not is_typed(v) else v) for k, v in obj.iteritems()])}
    elif isinstance(obj, set):
      return {'type': 'set', 'value': list(obj)}
    elif isinstance(obj, list):
      return {'type': 'list', 'value': obj}
    elif isinstance(obj, bool):
      return {'type': 'boolean', 'value': obj}
    elif isinstance(obj, int):
      return {'type': 'integer', 'value': obj}
    elif isinstance(obj, float):
      return {'type': 'float', 'value': obj}
    elif(isinstance(obj, basestring)):
      return {'type': 'string', 'value': obj}
    else:
      return None 

  def dumps(self, obj):
    return json.dumps(self.dump(obj))

  def load(self, data, type=None):
    is_typed = lambda x: isinstance(x, dict) and 'type' in x and 'value' in x

    if isinstance(data, dict):
      if not type and 'type' in data:
        type = data['type']

      if type and 'value' in data:
        data = data['value']

    if not type:
      raise ValueError('Type must be specified in order to unmarshal %s' % data)

    if type in DomainObjectFactory.TYPES and isinstance(data, dict):
      data = dict([(str(k), self.load(v) if is_typed(v) else v) for k, v in data.iteritems()])
      return DomainObjectFactory.get_instance(type, **data)

    elif (type == 'map' or type == 'sortedMap') and isinstance(data, dict):
      return dict([(k, self.load(v) if is_typed(v) else v) for k, v in data.iteritems()])

    elif (type == 'list' or type == 'set' or type == 'sortedSet') and isinstance(data, list):
      return [self.load(i) if is_typed(i) else i for i in data]

    elif (type == 'float' or type == 'integer' or type == 'boolean' or type == 'string'):
      return data

    else:
      return {'type': type, 'value': data}

  def loads(self, data, type=None):
    return self.load(json.loads(data), type)

class XmlMarshaler(Marshaler):
  def _is_element(self, node):
    return isinstance(node, xml.dom.minidom.Element)

  def _has_elements(self, node):
    for e in node.childNodes:
      if(self._is_element(e)):
        return True
    
    return False

  def _get_elements(self, node):
    return filter(self._is_element, node.childNodes)

  def _concat_text_nodes(self, node):
    node.normalize()
    children = [child.nodeValue for child in node.childNodes if isinstance(child, xml.dom.minidom.Text)]

    return ''.join(children)

  def dump(self, obj, doc=None):
    is_primitive  = lambda x: True in [isinstance(x, type) for type in [basestring, int, float]]
    is_labeled    = lambda x: isinstance(x, tuple) and isinstance(x[0], basestring)
    is_typed      = lambda x: isinstance(x, dict) and 'type' in x and 'value' in x

    if not doc:
      dom = xml.dom.minidom.getDOMImplementation()
      doc = dom.createDocument(None, 'root', None)

    if isinstance(obj, DomainObject):
      return self.dump((obj.type_hint(), {'type': obj.type_hint(), 'value': obj.get_members()}), doc)

    elif is_labeled(obj) and is_typed(obj[1]):
      return self.dump_typed_tuple(obj, doc)

    elif is_labeled(obj):
      label, value = obj

      if isinstance(value, DomainObject):
        return self.dump((label, {'type': value.type_hint(), 'value': value.get_members()}), doc)

      if isinstance(value, dict):
        return self.dump((label, {'type': 'map', 'value': value}), doc)

      elif isinstance(value, set):
        return self.dump((label, {'type': 'set', 'value': value}), doc)

      elif isinstance(value, list):
        return self.dump((label, {'type': 'list', 'value': value}), doc)

      elif isinstance(value, bool):
        return self.dump((label, {'type': 'boolean', 'value': value}), doc)

      elif isinstance(value, int):
        return self.dump((label, {'type': 'integer', 'value': value}), doc)

      elif isinstance(value, float):
        return self.dump((label, {'type': 'float', 'value': value}), doc)

      elif(isinstance(value, basestring)):
        return self.dump((label, {'type': 'string', 'value': value}), doc)

      else:
        raise TypeError('Cannot dump value of unknown type %s' % value)

    elif isinstance(obj, dict):
      return self.dump_dict(obj, doc)

    elif isinstance(obj, set):
      e = self.dump_list(obj, doc)
      e.setAttribute('type', 'set')
      return e

    elif isinstance(obj, list):
      return self.dump_list(obj, doc)

    elif isinstance(obj, bool):
      return self.dump_bool(obj, doc)

    elif is_primitive(obj):
      e = doc.createElement('item')
      f = doc.createTextNode(str(obj))
      e.appendChild(f)

      return e

    else:
      raise ValueError('Cannot marshal object %s' % obj)

  def dump_typed_tuple(self, t, doc):
    label, struct = t

    e = self.dump(struct['value'], doc)
    e.tagName = label
    e.setAttribute('type', struct['type'])

    if struct['type'] == 'permissions':
      for f in e.childNodes:
        if self._is_element(f) and f.tagName in struct['value']:
          f.setAttribute('access', struct['value'][f.tagName]['access'])

    return e

  def dump_dict(self, d, doc):
    e = doc.createElement('items')

    for i, j in d.iteritems():
      f = self.dump((i, j), doc)
      e.appendChild(f)
      e.setAttribute('type', 'map')

    return e

  def dump_list(self, l, doc):
    e = doc.createElement('items')

    for i in l:
      f = self.dump(('item', i), doc)
      e.appendChild(f)
      e.setAttribute('type', 'list')

    return e

  def dump_bool(self, b, doc):
    e = doc.createElement('item')
    f = doc.createTextNode(str(b).lower())
    e.appendChild(f)

    return e

  def dumps(self, obj):
    return self.dump(obj).toprettyxml(indent='  ')

  def load(self, data, type=None):
    if isinstance(data, xml.dom.minidom.Document):
      return self.load(data.documentElement, type)

    if data.hasAttribute('type'):
      type = data.getAttribute('type') if not type else type

    if type and self._is_element(data):
      if type in DomainObjectFactory.TYPES:
        return DomainObjectFactory.get_instance(type, **self.load(data, 'map'))

      elif type == 'map':
        return self.load_dict(data)

      elif type == 'sortedMap':
        return {'type': type, 'value': self.load_dict(data)}

      elif type == 'list':
        return self.load_list(data)

      elif type == 'set' or type == 'sortedSet':
        return {'type': type, 'value': self.load_list(data)}

      elif type == 'float' and data.hasChildNodes():
        return float(self._concat_text_nodes(data))

      elif type == 'integer' and data.hasChildNodes():
        return int(self._concat_text_nodes(data))

      elif type == 'boolean' and data.hasChildNodes():
        return bool(self._concat_text_nodes(data))

      elif type == 'string' and data.hasChildNodes():
        return self._concat_text_nodes(data)

      elif type == 'permissions' and data.hasChildNodes():
        data.normalize()
        value = self.load_dict(data)

        for e in self._get_elements(data):
          if e.tagName in value:
            value[e.tagName]['access'] = e.getAttribute('access')

        return DomainObjectMemberFactory.get_instance('permissions', value)

      elif data.hasChildNodes():
        try:
          data.normalize()

          if self._has_elements(data):
            value = self.load_dict(data)
          else:
            value = self.load(data, type='string')

          return DomainObjectMemberFactory.get_instance(type, value)

        except Exception as e:
          raise Exception('Cannot load object of type %s with value %s' % (type, data))

    elif data.hasChildNodes():
      if self._has_elements(data):
        return self.load_dict(data)
      else:
        return self.load(data, type='string')


  def load_dict(self, data):
    # output dict
    d = {}

    for e in data.childNodes:
      if self._is_element(e):
        k = e.nodeName.encode('ascii')
        v = self.load(e)

        if not k in d:
          d[k] = v

        else:
          # if d[k] is a list, append v
          if type(d[k]) == type([]) and len(d[k]):
            d[k].append(v)

          # construct list from d[k] and v
          else:
            d[k] = [d[k], v]

    return d

  def load_list(self, data):
    if data.hasChildNodes():
      return [self.load(i) for i in data.childNodes if isinstance(i, xml.dom.minidom.Element)]

    else:
      return []

  def loads(self, data, type=None):
    return self.load(xml.dom.minidom.parseString(data), type)

class DomainObject(object):
  """A base abstract class for Flow Domain Objects."""

  # latest instantiated marshaling REST client
  active_client = None

  # data member mapping of name -> type
  members = {
      'id'            : 'id',
      'creatorId'     : 'id',
      'creationDate'  : 'date',
      'lastEditorId'  : 'id',
      'lastEditDate'  : 'date'}

  def __init__(self, **kargs):
    self.set_members(**kargs)

  def __getattr__(self, name):
    if name in self.__dict__:
      return self.__dict__[name]
    elif name in self.__class__.members.keys():
      return None
    else:
      raise AttributeError()

  def __setattr__(self, name, value):
    if name in self.__class__.members.keys() and value is not None:
      type = self.__class__.members[name]

      if type in DomainObjectFactory.TYPES and isinstance(value, DomainObject):
        self.__dict__[name] = value

      elif type in DomainObjectFactory.TYPES and isinstance(value, dict):
        self.__dict__[name] = DomainObjectFactory.get_instance(type, **value)

      elif isinstance(value, dict) and 'type' in value and 'value' in value and value['type'] == type:
        self.__dict__[name] = value

      else:
        self.__dict__[name] = DomainObjectMemberFactory.get_instance(type, value)

    elif name in self.__class__.members.keys():
      self.__delattr__(name)

    else:
      raise AttributeError()

  def __delattr__(self, name):
    if name in self.__class__.members.keys():
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

  def get_member_type(self, name):
    member = self.__getattr__(name)
    return member['type'] if member else self.__class__.members['name']

  def get_member_value(self, name):
    member = self.__getattr__(name)
    return member['value'] if member else None

  def get_members(self):
    """Return a key-value map of the domain object's data members."""
    return dict(filter(
        lambda x: x[1] is not None,
        [(k, self.__getattr__(k)) for k in self.__class__.members.keys()]))

  def set_members(self, **kargs):
    """Set the data members of the domain object to the given key-value pairs."""
    for k, v in kargs.items():
      if k in self.__class__.members.keys():
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

    **Keyword args:**
      client (MarshalingClient): A marshaling REST client -- defaults to the current active client

    """
    active_client = self.resolve_client(client)
    uid = self.get_uid()
    id = self.id

    # remove id member before marshaling to avoid `'id' is not a member of this resource` messages
    del self.id

    data = active_client.marshals(self)
    self.id = id 

    if not uid:
      uri = self.__class__.class_bound_path()
      new = active_client.create(self.__class__, uri, data)
    else:
      uri = self.__class__.instance_bound_path(uid)
      new = active_client.update(self.__class__, uri, data)

    self.set_members(**new.get_members())
    return self

  def update(self, client=None, member=None):
    """Persist an object or one of its members in the Flow Platform.

    **Keyword args:**
      client (MarshalingClient): A marshaling REST client -- defaults to the current active client
      member (str): The name of data member to be updated (optional)

    """
    active_client = self.resolve_client(client)
    uid = self.get_uid()
    
    if not uid:
      raise Exception('Cannot update without \'id\' member set')

    if not member:
      new = self.save(active_client)
    else:
      uri = self.__class__.instance_bound_path(uid) + '/' + member
      data = active_client.marshals(self)
      new = active_client.update(self.__class__, uri, data)

    self.set_members(**new.get_members())
    return self

  def delete(self, client=None, member=None):
    """Remove an object or one of its members from the Flow Platform.

    **Keyword args:**
      client (MarshalingClient): A marshaling REST client -- defaults to the current active client
      member (str): The name of a data member to be deleted (optional)

    """
    active_client = self.resolve_client(client)
    uid = self.get_uid()

    if not uid:
      raise Exception('Cannot delete without \'id\' member set')

    if not member:
      uri = self.__class__.instance_bound_path(uid)
      return active_client.delete(self.__class__, uri)

    else:
      uri = self.__class__.instance_bound_path(uid) + '/' + member
      data = active_client.marshals(self)

      if active_client.delete(self.__class__, uri, data):
        self.__delattr__(member)

      return self

  @classmethod
  def resolve_client(cls, client):
    active_client = cls.active_client if not client else client

    if not active_client:
      raise ValueError('An active REST client is required')

    return active_client

  @classmethod
  def type_hint(cls):
    """The common string name of the domain object."""
    return cls.__name__.lower()

  @classmethod
  def class_bound_path(cls):
    """The uri path that governs all instances of this type."""
    return '/' + cls.type_hint()

  @classmethod
  def instance_bound_path(cls, id):
    """The uri path that governs a single instance of this type."""
    return '/'.join([cls.class_bound_path(), id]) 

  @classmethod
  def context_bound_path(cls, context=None):
    """The uri path that governs a subset of instances of this type, bounded by some specified context."""
    if not context:
      return cls.class_bound_path()
    else:
      return '/'.join([cls.class_bound_path(), context])

  @classmethod
  def find(cls, client=None, **kargs):
    """Find instances of this class in the Flow Platform.
    
    **Keyword args:**
      client (MarshalingClient): A marshaling REST client -- defaults to the current active client
      kargs (dict): dictionary containing one of 'query' or 'filter', \
          and all or none of 'start', 'limit', 'sort', and 'order'

    """
    active_client = cls.resolve_client(client)

    if 'id' in kargs:
      id = kargs.pop('id')
      value = id['value'] if isinstance(id, dict) and 'type' in id and 'value' in id else id
      uri = cls.instance_bound_path(value)
      return active_client.find_one(cls, uri)
    else:
      if 'flowId' in kargs:
        flow_id = kargs.pop('flowId')
        value = flow_id['value'] if isinstance(flow_id, dict) and 'type' in flow_id and 'value' in flow_id else flow_id
        uri = cls.context_bound_path(value)
      else:
        uri = cls.class_bound_path()

      opts = dict([(opt, kargs.pop(opt)) for opt in \
          filter(lambda x: x in kargs, ['query', 'filter', 'start', 'limit', 'sort', 'order'])])

      new = cls(**kargs)
      typed_kargs = new.get_members()
      kargs.update(typed_kargs)
      del new

      return active_client.find_many(cls, uri, kargs, **opts)

class Application(DomainObject):
  """A user generated application comprised of a template and a hierarchy of flows."""

  members = dict(DomainObject.members.items() + [
      ('name', 'string'),
      ('displayName', 'string'),
      ('description', 'string'),
      ('email', 'string'),
      ('url', 'url'),
      ('icon', 'url'),
      ('isDiscoverable', 'boolean'),
      ('isInviteOnly', 'boolean'),
      ('applicationTemplate', 'applicationTemplate'),
      ('flowRefs', 'set'),
      ('permissions', 'permissions')])

  def __init__(self, **kargs):
    super(Application, self).__init__(**kargs)

class Flow(DomainObject):
  """A container for drops."""

  members = dict(DomainObject.members.items() + [
      ('name', 'string'),
      ('description', 'string'),
      ('path', 'path'),
      ('filter', 'string'),
      ('location', 'location'),
      ('local', 'boolean'),
      ('template', 'constraints'),
      ('icon', 'url'),
      ('permissions', 'permissions'),
      ('dropPermissions', 'permissions')])

  def __init__(self, **kargs):
    super(Flow, self).__init__(**kargs)

class Drop(DomainObject):
  """An atomic unit of platform data with map-like behavior."""

  members = dict(DomainObject.members.items() + [
      ('flowId', 'id'),
      ('path', 'path'),
      ('elems', 'map'),
      ('flags', 'flags'),
      ('flag', 'string'),
      ('ratings', 'rating'),
      ('rating', 'integer'),
      ('weight', 'integer')])

  FLAGS = ['adult', 'spam']

  def __init__(self, **kargs):
    super(Drop, self).__init__(**kargs)

  def get_uid(self):
    flow_id = self.__getattr__('flowId')
    id = self.__getattr__('id')

    if isinstance(flow_id, basestring):
      flow_id = flow_id
    elif isinstance(flow_id, dict) and 'value' in flow_id:
      flow_id = flow_id['value']
    else:
      flow_id = None

    if isinstance(id, basestring):
      id = id
    elif isinstance(id, dict) and 'value' in id:
      id = id['value']
    else:
      id = None

    if not flow_id or not id:
      return None
    else:
      return '%s/%s' % (flow_id, id)

  def flag(self, value, client=None):
    active_client = self.resolve_client(client)
    uid = self.get_uid()
    value = value.lower()

    if value not in Drop.FLAGS:
      raise ValueError('Unsupported flag value')

    if not uid:
      raise ValueError('Valid id required')

    flag = Drop(flag = value)
    uri = self.instance_bound_path(uid)
    data = active_client.marshals(flag)
    response = active_client.http_put(uri, data)

    new = self.__class__(**Marshaler.kargify(active_client.response_body(response)))
    self.set_members(**new.get_members())
    return self

  def rate(self, value, client=None):
    active_client = self.resolve_client(client)
    uid = self.get_uid()

    if value < 0 or value > 10: 
      raise ValueError('Unsupported rating value')

    if not uid:
      raise ValueError('Valid id required')

    rating = Drop(rating = value)
    uri = self.instance_bound_path(uid)
    data = active_client.marshals(rating)
    response = active_client.http_put(uri, data)

    new = self.__class__(**Marshaler.kargify(active_client.response_body(response)))
    self.set_members(**new.get_members())
    return self

  def weight(self, value, client=None):
    active_client = self.resolve_client(client)
    uid = self.get_uid()

    if value < 0 or value > 1000: 
      raise ValueError('Unsupported weight value')

    if not uid:
      raise ValueError('Valid id required')

    weight = Drop(weight = value)
    uri = self.instance_bound_path(uid)
    data = active_client.marshals(weight)
    response = active_client.http_put(uri, data)

    new = self.__class__(**Marshaler.kargify(active_client.response_body(response)))
    self.set_members(**new.get_members())
    return self

class Enum(DomainObject):
  """A flow that is a container for enumerable reference values."""

  members = dict(DomainObject.members.items() + [
      ('name', 'string'),
      ('path', 'path'),
      ('values', 'list'),
      ('permissions', 'permissions')])

  def __init__(self, **kargs):
    super(Enum, self).__init__(**kargs)

class File(DomainObject):
  """A reference to a file that is stored on the Flow Platform file server."""

  members = dict(DomainObject.members.items() + [
      ('name', 'string'),
      ('mimeType', 'string'),
      ('contents', 'bytes')])

  def __init__(self, **kargs):
    super(File, self).__init__(**kargs)

class Group(DomainObject):
  """A collection of identities that can act as a single persona."""

  members = dict(DomainObject.members.items() + [
      ('name', 'string'),
      ('displayName', 'string'),
      ('identities', 'set'),
      ('permissions', 'permissions'),
      ('identityPermissions', 'permissions')])

  def __init__(self, **kargs):
    super(Group, self).__init__(**kargs)

class Identity(DomainObject):
  """A user's persona."""

  members = dict(DomainObject.members.items() + [
      ('firstName', 'string'),
      ('lastName', 'string'),
      ('alias', 'string'),
      ('avatar', 'url'),
      ('groupIds', 'set'),
      ('userId', 'id'),
      ('appIds', 'set'),
      ('permissions', 'permissions')])

  def __init__(self, **kargs):
    super(Identity, self).__init__(**kargs)

class Track(DomainObject):
  """Data pipeline to connect one flow to another."""

  members = dict(DomainObject.members.items() + [
      ('from', 'path'),
      ('to', 'path'),
      ('filterString', 'string'),
      ('transformFunction', 'transformFunction'),
      ('permissions', 'permissions')])

  def __init__(self, **kargs):
    super(Track, self).__init__(**kargs)

class User(DomainObject):
  """A system user and a container for identities."""

  members = dict(DomainObject.members.items() + [
      ('email', 'email'),
      ('initialEmail', 'email'),
      ('password', 'password'),
      ('defaultIdentity', 'identity'),
      ('identityIds', 'set'),
      ('permissions', 'permissions')])

  def __init__(self, **kargs):
    super(User, self).__init__(**kargs)

class ApiTask(DomainObject):
  """A schedulable task for importing data from a REST request."""

  members = dict(DomainObject.members.items() + [
    ('modifiedDate', 'date'),
    ('lastExecutedDate', 'date'),
    ('executorId', 'id'),
    ('source', 'string'),
    ('name', 'string'),
    ('description', 'string'),
    ('periodicity', 'integer')])

  def __init__(self, **kargs):
    super(ApiTask, self).__init__(**kargs)

  @classmethod
  def type_hint(cls):
    return 'apiTask'

  @classmethod
  def class_bound_path(cls):
    return '/api-task'

class RssTask(DomainObject):
  """A schedulable task for importing data from a RSS or Atom feed."""

  members = dict(DomainObject.members.items() + [
    ('feed', 'rssFeed'),
    ('status', 'integer'),
    ('periodicity', 'integer'),
    ('lastHashSet', 'set'),
    ('executorId', 'id'),
    ('lastExecutedDate', 'date'),
    ('modifiedDate', 'date')])

  def __init__(self, **kargs):
    super(RssTask, self).__init__(**kargs)

  @classmethod
  def type_hint(cls):
    return 'rssTask'

  @classmethod
  def class_bound_path(cls):
    return '/rss-task'

class DomainObjectIterator(object):
  def __init__(self, objs=None, total=None):
    self._total = total
    self.objs = objs if objs else []

  def total(self):
    if not self._total:
      raise ValueError('Total size of set unknown. To obtain the size of the iterator invoke size().')

    return self._total

  def size(self):
    return len(self.objs)

  def __iter__(self):
    for i in self.objs: yield i

  def __getitem__(self, i):
    return self.objs[i]

class DomainObjectFactory(object):
  """Factory class to instantiate domain objects based upon their string type-hints."""

  TYPES = [
    'application',
    'flow',
    'drop',
    'enum',
    'file',
    'group',
    'identity',
    'track',
    'user',
    'apiTask',
    'rssTask']

  @staticmethod
  def get_instance(type, **kargs):
    """Return an instance of a class by a given type-hint.

    Keyword arguments should be the key value mapping of 
    members to be set for the instance to be returned.

    >>> DomainObjectFactory().get_instance('user', email='alice@example.com')

    """
    if type == 'application':
      return Application(**kargs)
    elif type == 'flow':
      return Flow(**kargs)
    elif type == 'drop':
      return Drop(**kargs)
    elif type == 'file':
      return File(**kargs)
    elif type == 'group':
      return Group(**kargs)
    elif type == 'identity':
      return Identity(**kargs)
    elif type == 'track':
      return Track(**kargs)
    elif type == 'user':
      return User(**kargs)
    elif type == 'apiTask':
      return ApiTask(**kargs)
    elif type == 'rssTask':
      return RssTask(**kargs)
    else:
      raise ValueError('Unknown type \'%s\' supplied for instantiation' % type)

class DomainObjectMemberFactory(object):
  """Factory class to instantiate domain object members based upon their string type-hints."""

  NATIVE_TYPES = [
      'string',
      'boolean',
      'integer',
      'float',
      'list',
      'set',
      'map']

  LABELED_STRING_TYPES = [
      'id',
      'path',
      'email',
      'password',
      'flowRef',
      'url',
      'upc',
      'vin', 
      'phone',
      'isbn',
      'bytes']

  LABELED_INT_TYPES = []

  LABELED_LIST_TYPES = [
      'constraints']

  LABELED_DICT_TYPES = [
      'location',
      'text',
      'media',
      'color',
      'range',
      'weight',
      'duration',
      'length',
      'dropRef',
      'permissions', 
      'constraint',
      'applicationTemplate',
      'flowTemplate',
      'trackTemplate',
      'dropTemplate',
      'transformFunction',
      'flags',
      'rating',
      'rssFeed']

  @staticmethod
  def get_instance(type, value):
    # regular expression patterns can be used in place of strings, or any string-like type
    if (type == 'string' or type in DomainObjectMemberFactory.LABELED_STRING_TYPES) \
      and isinstance(value, re._pattern_type):
      return {'type': 'expression', 'value': {'operator': 'regex', 'operand': value.pattern}}

    if type in DomainObjectMemberFactory.NATIVE_TYPES:
      if (type == 'string' and isinstance(value, basestring)) \
        or (type == 'boolean' and isinstance(value, bool)) \
        or (type == 'integer' and isinstance(value, int)) \
        or (type == 'float' and (isinstance(value, float) or isinstance(value, int))) \
        or (type == 'list' and isinstance(value, list)) \
        or (type == 'map' and isinstance(value, dict)):
        return {'type': type, 'value': value}

      elif (type == 'set' and (isinstance(value, set) or isinstance(value, list))) :
        return {'type': type, 'value': list(value)}

      else:
        raise NotImplementedError('Cannot create instance for type-value pair (%s, %s)' % (type, value))

    if type in DomainObjectMemberFactory.LABELED_STRING_TYPES and isinstance(value, basestring):
      return {'type': type, 'value': value}

    if type in DomainObjectMemberFactory.LABELED_INT_TYPES and isinstance(value, int):
      return {'type': type, 'value': value}

    if type in DomainObjectMemberFactory.LABELED_LIST_TYPES and isinstance(value, list):
      return {'type': type, 'value': value}

    if type in DomainObjectMemberFactory.LABELED_LIST_TYPES and isinstance(value, dict):
      return {'type': type, 'value': value.popitem()[1]}

    if type in DomainObjectMemberFactory.LABELED_DICT_TYPES and isinstance(value, dict):
      return {'type': type, 'value': value}

    # build date from an integer value or string that represents milliseconds since epoch
    if type == 'date' and (isinstance(value, basestring) or isinstance(value, int)):
      return {'type': type, 'value': int(value)}

    # build date from native datetime object
    if type == 'date' and isinstance(value, datetime.datetime):
      value = (time.mktime(value.timetuple()) + (value.microsecond / 1000000)) * 1000
      return {'type': type, 'value': int(value)}

    # build date from native date object
    if type == 'date' and isinstance(value, datetime.date):
      value = time.mktime(value.timetuple()) * 1000
      return {'type': type, 'value': int(value)}

    else:
      raise NotImplementedError('Cannot create instance for type-value pair (%s, %s)' % (type, value))

  @classmethod
  def id(cls, value):
    return cls.get_instance('id', value)

  @classmethod
  def path(cls, value):
    return cls.get_instance('path', value)

  @classmethod
  def email(cls, value):
    return cls.get_instance('email', value)

  @classmethod
  def url(cls, value):
    return cls.get_instance('url', value)

  @classmethod
  def upc(cls, value):
    return cls.get_instance('upc', value)

  @classmethod
  def vin(cls, value):
    return cls.get_instance('vin', value)

  @classmethod
  def phone(cls, value):
    return cls.get_instance('phone', value)

  @classmethod
  def isbn(cls, value):
    return cls.get_instance('isbn', value)

  @classmethod
  def constraints(cls, *values):
    return cls.get_instance('constraints', [cls.get_instance('constraint', i) for i in values])

  @classmethod
  def applicationTemplate(cls, flows, tracks):
    return cls.get_instance('applicationTemplate', {
      'flowTemplates': [cls.get_instance('flowTemplate', x) for x in flows],
      'trackTemplates': [cls.get_instance('trackTemplate', x) for x in tracks]})

class DomainFactory(DomainObjectMemberFactory):
  """Used only to save typing during Domain Object construction."""

  @classmethod
  def application(**kargs):
    return DomainObjectFactory.get_instance('application', **kargs)

  @classmethod
  def flow(**kargs):
    return DomainObjectFactory.get_instance('flow', **kargs)

  @classmethod
  def drop(**kargs):
    return DomainObjectFactory.get_instance('drop', **kargs)

  @classmethod
  def enum(**kargs):
    return DomainObjectFactory.get_instance('enum', **kargs)

  @classmethod
  def file(**kargs):
    return DomainObjectFactory.get_instance('file', **kargs)

  @classmethod
  def group(**kargs):
    return DomainObjectFactory.get_instance('group', **kargs)

  @classmethod
  def identity(**kargs):
    return DomainObjectFactory.get_instance('identity', **kargs)

  @classmethod
  def track(**kargs):
    return DomainObjectFactory.get_instance('track', **kargs)

  @classmethod
  def user(**kargs):
    return DomainObjectFactory.get_instance('user', **kargs)

  @classmethod
  def apiTask(**kargs):
    return DomainObjectFactory.get_instance('apiTask', **kargs)

  @classmethod
  def rssTask(**kargs):
    return DomainObjectFactory.get_instance('rssTask', **kargs)

try:
  from twisted.internet import reactor, task
  from twisted.names.srvconnect import SRVConnector
  from twisted.words.protocols.jabber import client, jid, xmlstream

  XMPP_HOST = 'xmpp.flow.net'

  class XmppClient(object):
    """A base class for communication with the Flow Platform's
    publish-subscribe model over the XMPP protocol.
    """

    C2S_PORT = 5222

    def __init__(self, jid_str, key, secret, actor=None):
      md = hashlib.sha1()

      # is it an identity-scoped JID?
      if len(jid_str.split('#')) > 1:
        if not actor: raise Exception('Actor is required for identity JIDs')
        md.update(key + secret + actor)

      else:
        md.update(key + secret)

      self.logger = logging.getLogger('flow.XmppClient')
      self.jid = jid.JID(jid_str)
      self.password = md.hexdigest()
      self.is_authenticated = False
      self.is_connected = False
      self.keepalive = task.LoopingCall(self._announce)

      factory = client.XMPPClientFactory(self.jid, self.password)

      factory.addBootstrap(
          xmlstream.STREAM_CONNECTED_EVENT,
          self._on_connect)

      factory.addBootstrap(
          xmlstream.STREAM_END_EVENT,
          self._on_disconnect)

      factory.addBootstrap(
          xmlstream.STREAM_AUTHD_EVENT,
          self._on_authenticate)

      factory.addBootstrap(
          xmlstream.INIT_FAILED_EVENT,
          self._on_err)

      XmppClient.Connector(reactor, self.jid.host, factory).connect()

    def set_logger_level(self, level):
      self.logger.setLevel(level)

    def set_logger_file(self, filename):
      self.logger.addHandler(logging.FileHandler(filename))

    def start(self):
      self.logger.debug('start')
      reactor.run()

    def incoming_packet_callback(self, buf):
      pass

    def outgoing_packet_callback(self, buf):
      pass

    def connect_callback(self):
      pass

    def authenticate_callback(self):
      pass

    def disconnect_callback(self):
      pass

    def _announce(self):
      self.stream.send('<presence />')

    def _on_data_in(self, buffer):
      """Log incoming data and trigger incoming callback if authenticated"""
      self.logger.debug('<< %s' % unicode(buffer, 'utf-8').encode('ascii', 'replace'))
      if self.is_authenticated: self.incoming_packet_callback(buffer)

    def _on_data_out(self, buffer):
      """Log outgoing data and trigger outgoing callback if authenticated"""
      self.logger.debug('>> %s' % unicode(buffer, 'utf-8').encode('ascii', 'replace'))
      if self.is_authenticated: self.outgoing_packet_callback(buffer)

    def _on_connect(self, stream):
      """Bind data processing routines and trigger connect callback"""
      self.logger.info('++ %s connected' % self)
      self.is_connected = True
      self.stream = stream
      stream.rawDataInFn = self._on_data_in
      stream.rawDataOutFn = self._on_data_out
      self.connect_callback()

    def _on_disconnect(self, stream):
      """Stop event-loop and trigger disconnect callback"""
      self.logger.info('++ %s disconnected' % self)
      self.is_connected = False
      self.is_authenticated = False
      reactor.callLater(0.5, reactor.stop)
      self.disconnect_callback()

    def _on_authenticate(self, stream):
      """Trigger authentication callback"""
      self.logger.info('++ %s authenticated' % self)
      self.keepalive.start(10)
      self.is_authenticated = True
      # reassign JID since we now have a valid resource id
      self.jid = self.stream.authenticator.jid
      self.authenticate_callback()

    def _on_err(self, stream):
      """Close connection during initialization failure"""
      self.logger.info('-- %s failed initialization' % self)
      self.stream.sendFooter()

    class Connector(SRVConnector):
      def __init__(self, reactor, domain, factory):
        SRVConnector.__init__(self, reactor, 'flow.XmppClient', domain, factory)

      def pickServer(self):
        host, port = SRVConnector.pickServer(self)

        if not self.servers and not self.orderedServers:
          port = XmppClient.C2S_PORT

        return host, port

except ImportError:
  class XmppClient(object):
    def __init__(self, jid_str, secret):
      raise Exception('python module `twisted` required')
