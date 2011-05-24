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

API_HOST = 'api.flow.net'
API_PORT = 80

FILE_SERVER_HOST = 'file.flow.net'
FILE_SERVER_PORT = 80

class RestClient(object):
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
    self.ops = dict([
      (RestClient.MIME_JSON, JsonRestOps(self)),
      (RestClient.MIME_XML, XmlRestOps(self))])

    self.logger = logging.getLogger('flow.RestClient')
    self.set_logger_level(logging.DEBUG)

  def set_actor(self, actor):
    self.actor = actor

  def set_opts(self, opts):
    if 'headers' not in opts: opts['headers'] = {}
    if 'params' not in opts: opts['params'] = {}

    self.opts = opts

  def set_op(self, mime_type, op):
    self.ops[mime_type] = op

  def set_logger_level(self, level):
    self.logger.setLevel(level)

  def set_logger_file(self, filename):
    self.logger.addHandler(logging.FileHandler(filename))

  def get_header(self, method, name):
    if 'headers' in self.opts \
        and method in self.opts['headers'] \
        and name in self.opts['headers'][method]:
      return self.opts['headers'][method][name]
    else:
      return RestClient.DEFAULT_HEADERS[method][name]

  def get_param(self, name):
    if 'params' in self.opts \
        and name in self.opts['params'][name]:
      return self.opts['params'][name]
    else:
      return None

  def get_op(self, mime_type):
    if mime_type in self.ops:
      return self.ops[mime_type]
    else:
      raise TypeError()

  def _mk_creds(self):
    headers = {
        'X-Actor': self.actor,
        'X-Key': self.key,
        'X-Timestamp': self._mk_timestamp()}

    headers['X-Signature'] = self._mk_signature(headers)
    return headers

  def _mk_timestamp(self):
    return str(int(time.time() * 1000))

  def _mk_signature(self, creds):
    md = hashlib.sha1()

    for pair in sorted(creds.iteritems()):
      md.update(str(pair[0].lower()) + ':' + str(pair[1]))
    else:
      md.update(self.secret)

    return md.hexdigest()

  def _mk_opts(self, opts):
    if 'headers' not in opts: opts['headers'] = {}
    if 'params' not in opts: opts['params'] = {}

    opts['headers'].update(self.opts['headers'])
    opts['params'].update(self.opts['params'])

    return opts

  def _mk_headers(self, default, given):
    if given:
      headers = dict(default, **given)
    else:
      headers = default

    headers['User-Agent'] = 'flow-python-client_%s' % __version__
    return dict(headers, **self._mk_creds())

  def _mk_url(self, base, params):
    if params:
      return '%s?%s' % (base, urllib.urlencode(params))
    else:
      return base

  def _mk_request(self, url, method, data=None, opts={}):
    opts = self._mk_opts(opts)
    url = self._mk_url(url, opts['params'])
    headers = self._mk_headers(
        RestClient.DEFAULT_HEADERS[method], opts['headers'])

    return self.request(url, method, data, headers)

  def request(self, url, method, data=None, headers={}):
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

  """Raw data operations"""
  def http_get(self, url, opts={}):
    return self._mk_request(url, 'GET', None, opts)

  def http_post(self, url, data, opts={}):
    return self._mk_request(url, 'POST', data, opts)

  def http_put(self, url, data, opts={}):
    return self._mk_request(url, 'PUT', data, opts)

  def http_delete(self, url, opts={}):
    return self._mk_request(url, 'DELETE', None, opts)

  """DomainObject operations"""
  def save(self, obj):
    if obj.id == None:
      return self.create(obj)
    else:
      return self.update(obj)

  def create(self, obj):
    content_type = self.get_header('POST', 'Content-type')
    return self.get_op(content_type).create(obj)

  def update(self, obj):
    content_type = self.get_header('PUT', 'Content-type')
    return self.get_op(content_type).update(obj)

  def delete(self, obj):
    accept = self.get_header('DELETE', 'Accept')
    return self.get_op(accept).delete(obj)

  def find(self, obj):
    accept = self.get_header('GET', 'Accept')

    if obj.id == None:
      return self.get_op(accept).find_one(obj)
    else:
      return self.get_op(accept).find_many(obj)

  def search(self, obj):
    accept = self.get_header('GET', 'Accept')
    return self.get_op(accept).search(obj)

  """Misc. utilities"""
  def oauth_uri(self, path, params=None):
    return 'http://%s/oauth%s%s' % (
        API_HOST + ':' + str(API_PORT), path,
        '?' + urllib.urlencode(params) if params else '')

class RestOps(object):
  def __init__(self, client):
    self.client = client

  def is_response_ok(self, response):
    raise NotImplemented('Implementation of this method required.')

  def get_response_body(self, response):
    raise NotImplemented('Implementation of this method required.')

  def marshal(self, obj):
    raise NotImplemented('Implementation of this method required.')

  def unmarshal(self, obj, data):
    return obj.hydrate(**data)

  def decode_unicode_types(self, data):
    if isinstance(data, unicode):
      return str(data)
    elif isinstance(data, dict):
      return dict(map(self.decode_unicode_types, data.iteritems()))
    elif isinstance(data, (list, tuple, set, frozenset)):
      return type(data)(map(self.decode_unicode_types, data))
    else:
      return data

  def create(self, obj):
    uri = '/%s' % obj.__class__.__name__.lower()
    data = self.marshal(obj)

    return obj.hydrate(
        **self.get_response_body(self.client.http_post(uri, data)))

  def update(self, obj):
    uri = '/%s/%s' % (obj.__class__.__name__.lower(), obj.guid())
    data = self.marshal(obj)

    return obj.hydrate(
        **self.get_response_body(self.client.http_put(uri, data)))

  def delete(self, obj):
    uri = '/%s/%s' % (obj.__class__.__name__.lower(), obj.guid())
    return self.get_response_body(self.client.http_delete(uri))

  def find_one(self, obj):
    uri = '/%s/%s' % (obj.__class__.__name__.lower(), obj.guid())
    return self.get_response_body(self.client.http_get(uri))

  def find_many(self, obj, offset=0, limit=10, sort='creationDate', order='desc'):
    uri = '/%s' % obj.__class__.__name__.lower()
    data = self.marshal(obj)
    opts = {'params': None}
    return self.get_response_body(self.client.http_get(uri, opts))

  def search(self, obj, query, offset=0, limit=10, sort='creationDate', order='desc'):
    uri = '/search/%s' % obj.__class__.__name__.lower()
    return self.get_response_body(self.client.http_get(uri))

class RestOpsException(Exception):
  pass

class JsonRestOps(RestOps):
  def __init__(self, client):
    super(JsonRestOps, self).__init__(client)
    client.set_opts({'params': {'hints': 0}})

  def parse_unicode(self, data):
    if isinstance(data, unicode):
      return str(data)
    elif isinstance(data, dict):
      return dict(map(self.decode_unicode_types, data.iteritems()))
    elif isinstance(data, (list, tuple, set, frozenset)):
      return type(data)(map(self.decode_unicode_types, data))
    else:
      return data

  def parse_response(self, raw_response):
    try:
      return self.parse_unicode(json.loads(raw_response))

    except ValueError as e:
      raise RestOpsException('JSON response data could not be parsed')

  def is_response_ok(self, response):
    if isinstance(response, basestring):
      response = self.parse_response(response)

    return ('head' in response
      and 'body' in response
      and 'ok' in response['head']
      and response['head']['ok'])

  def get_response_body(self, response):
    if isinstance(response, basestring):
      response = self.parse_response(response)

    if self.is_response_ok(response):
      return response['body']
    else:
      raise RestOpsException('Response status not \'ok\'')

  def marshal(self, obj):
    return obj.to_json(stringify=True)

  def unmarshal(self, obj, data):
    return obj.hydrate(**data)

class XmlRestOps(RestOps):
  def parse_response(self, raw_response):
    raise RestOpsException('XML response data could not be parsed')

  def is_response_ok(self, response):
    if isinstance(response, basestring):
      response = self.parse_response(response)

    raise RestOpsException('Response status no \'ok\'')

  def get_response_body(self, response):
    if isinstance(response, basestring):
      response = self.parse_response(response)

    if self.is_response_ok(response):
      return response
    else:
      raise RestOpsException('Response status not \'ok\'')

  def marshal(self, obj):
    return obj.to_xml(stringify=True)

  def unmarshal(self, obj, data):
    return obj.hydrate(**data)

class DomainObject(object):
  members = [
      'id',
      'creator',
      'creationDate',
      'lastEditDate']

  def __init__(self, **kargs):
    self.hydrate(**kargs)

  def __getattr__(self, name):
    if name in self.__dict__:
      return self.__dict__[name]
    elif name in self.__class__.members:
      return None
    else:
      raise AttributeError()

  def __setattr__(self, name, value):
    if name in self.__class__.members:
      self.__dict__[name] = value
    else:
      raise AttributeError()

  def guid(self):
    return self.__getattr__('id')

  def hydrate(self, **kargs):
    for k, v in kargs.items():
      if k in self.__class__.members:
        self.__setattr__(k, v)

    return self

  def to_json(self, stringify=False):
    def to_json_field(k, v):
      if(isinstance(v, dict)):
        return (k, v)
      elif(isinstance(v, basestring)):
        return (k, {'type': 'string', 'value': v})
      elif(isinstance(v, int)):
        return (k, {'type': 'integer', 'value': v})
      elif(isinstance(v, float)):
        return (k, {'type': 'float', 'value': v})
      elif(isinstance(v, list)):
        return (k, {'type': 'list', 'value': v})
      else:
        return (k, None)

    json_dict = dict([to_json_field(k, v) \
        for k, v in self.__dict__.items()])

    if stringify:
      return json.dumps(json_dict)
    else:
      return json_dict

  def to_xml(self, stringify=False):
    pass

class Application(DomainObject):
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
  members = DomainObject.members + [
      'path',
      'elems']

  def __init__(self, **kargs):
    super(Drop, self).__init__(**kargs)

  def guid(self):
    bucket_id = self.__getattr__('bucketId')
    id = super(Drop, self).guid()

    return '%s/%s' % (bucket_id, id)

class File(DomainObject):
  members = DomainObject.members + [
      'name',
      'mimeType',
      'contents']

  def __init__(self, **kargs):
    super(File, self).__init__(**kargs)

class Group(DomainObject):
  members = DomainObject.members + [
      'name',
      'displayName',
      'identities',
      'permissions',
      'identityPermissions']

  def __init__(self, **kargs):
    super(Group, self).__init__(**kargs)

class Identity(DomainObject):
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
  members = DomainObject.members + [
      'from',
      'to',
      'filterString',
      'transformFunction',
      'permissions']

  def __init__(self, **kargs):
    super(Track, self).__init__(**kargs)

class User(DomainObject):
  members = DomainObject.members + [
      'email',
      'password',
      'permissions']

  def __init__(self, **kargs):
    super(User, self).__init__(**kargs)

if __name__ == '__main__':
  KEY     = sys.argv[1]
  SECRET  = sys.argv[2]
  ACTOR   = '000000000000000000000001'

  client = RestClient(KEY, SECRET, ACTOR)
  client.set_logger_file('client.out')

  app_a = Application(
      name='lion_king',
      description='the lion king',
      email='simba@priderock.org',
      url='http://priderock.org')

  app_b = Application(
      name='hakuna_matata',
      description='songs from the lion king',
      email='simba@priderock.org',
      url='http://songs.priderock.org')

  client.save(app_a)

  client.find(app_a)

  client.delete(app_a)

  """
  Application.find(name='lion_king')
  Application.find(email='simba@priderock.org')
  Application.search(query='lion', limit=2)

  lion_king_app['url'] = 'http://lionking.priderock.org'
  lion_king_app.save()
  lion_king_app.load()
  lion_king_app.delete()
  hakuna_matata_app.delete()
  """

