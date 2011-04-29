import os, sys, logging
import httplib, urllib, json
import time, hashlib

class Client(object):
  URI     = 'api.flow.net'
  FS_URI  = 'file.flow.net'
  PORT    = 80

  MIME_JSON = 'application/json'
  MIME_XML  = 'text/xml'

  DEFAULT_HEADERS = {
    'GET'     : { 'Accept' : MIME_JSON },
    'POST'    : { 'Accept' : MIME_JSON, 'Content-type' : MIME_JSON },
    'PUT'     : { 'Accept' : MIME_JSON, 'Content-type' : MIME_JSON },
    'DELETE'  : { 'Accept' : MIME_JSON }
  }

  def __init__(self, key, secret, actor=None):
    if actor is not None: self.actor = actor

    self.key = key
    self.secret = secret
    self.opts = dict([('headers', {}), ('params', {})])
    self.cache = None
    self.logger = logging.getLogger('flow.Client')
    self.set_logger_level(logging.DEBUG)

  def set_actor(self, actor):
    self.actor = actor

  def set_opts(self, opts):
    if 'headers' not in opts: opts['headers'] = {}
    if 'params' not in opts: opts['params'] = {}

    self.opts = opts

  def set_cache(self, cache):
    self.cache = cache

  def set_logger_level(self, level):
    self.logger.setLevel(level)

  def set_logger_file(self, filename):
    self.logger.addHandler(logging.FileHandler(filename))

  def _mk_cache_key(self, url, headers):
    filtered_headers = dict(filter(
      lambda x: x[0] != 'X-Timestamp' or x[0] != 'X-Signature',
      headers.items()))

    return '%s:%s' % (url, pickle.loads(filtered_headers))
  
  def _mk_creds(self):
    headers = {
        'X-Actor': self.actor,
        'X-Key': self.key,
        'X-Timestamp' : self._mk_timestamp()}

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

    headers['User-Agent'] = 'flow-python-client_0.1.1'
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
        Client.DEFAULT_HEADERS[method], opts['headers'])

    return self.request(url, method, data, headers)

  def request(self, url, method, data=None, headers={}):
    if self.cache is not None: 
      key = self._mk_cache_key(url, headers)
      cached = False

    else: cached = False

    if cached:
      self.logger.debug('-- Begin Cache Request --')
      self.logger.debug('KEY> %s\n' % key)
      self.logger.debug('VALUE> %s\n' % value)
      self.logger.debug('-- End Cache Request --\n')

    else:
      data = data.encode('utf-8') if data else None
      conn = httplib.HTTPConnection(Client.URI + ':' + str(Client.PORT))
      conn.request(method, url, data, headers)
      response = conn.getresponse()
      response_str = response.read().decode('utf-8')

      self.logger.debug('-- Begin REST Request --')
      self.logger.debug('METHOD> %s\n' % method)
      self.logger.debug('URL> %s\n' % url)
      self.logger.debug('BODY>\n%s\n' % data)
      self.logger.debug('HEADERS>\n%s\n' % headers)
      self.logger.debug('RESPONSE>\n%s' % response_str)
      self.logger.debug('-- End REST Request --\n')

      return response_str

  def get(self, url, opts={}):
    return self._mk_request(url, 'GET', None, opts)

  def post(self, url, data, opts={}):
    return self._mk_request(url, 'POST', data, opts)

  def put(self, url, data, opts={}):
    return self._mk_request(url, 'PUT', data, opts)

  def delete(self, url, opts={}):
    return self._mk_request(url, 'DELETE', None, opts)

  def oauth_uri(self, path, params=None):
    return 'http://%s/oauth%s%s' % (
        Client.URI + ':' + str(Client.PORT), path,
        '?' + urllib.urlencode(params) if params else '')

from flow_utils import *

class ClientOps(object):
  def __init__(self, client):
    client.set_opts({'params': {'hints': 0}})
    self.client = client

  def _response_body(self, json_response_str, guard_fn):
    try:
      json_response = json.loads(json_response_str)

      if guard_fn(json_response):
        return json_response['body']
      else:
        raise ClientOpsException(json_response)

    except ClientOpsException as e:
      raise e

    except ValueError as e:
      raise ClientOpsException(json_response_str)

  def _response_is_ok(self, json_response):
    return ('head' in json_response
        and 'body' in json_response
        and 'ok' in json_response['head']
        and json_response['head']['ok'])

  def _response_has_results(self, json_response):
    return (self._response_is_ok(json_response)
        and len(json_response['body']) > 0)

  def _pop_pargs_from_kwargs(self, *pargs, **kwargs):
    popped = dict()

    for parg in list(pargs):
      if parg in kwargs: popped.update({parg: kwargs[parg]})

    return popped

  def create(self, uri, data):
    return self._response_body(
      self.client.post(uri, data),
      self._response_is_ok)

  def update(self, uri, data):
    return self._response_body(
      self.client.put(uri, data),
      self._response_is_ok)

  def delete(self, uri):
    return self._response_body(
      self.client.delete(uri),
      self._response_is_ok)

  def find_one(self, uri):
    return self._response_body(
        self.client.get(uri),
        self._response_is_ok)

  def find_many(self, uri, params):
    return self._response_body(
        self.client.get(uri, {'params': params}),
        self._response_is_ok)

  @accepts_kwargs(APPLICATION_FIELDS)
  def create_application(self, **kwargs):
    return self.create('/application', json.dumps(kwargs))

  @accepts_kwargs(BUCKET_FIELDS)
  def create_bucket(self, **kwargs):
    return self.create('/bucket', json.dumps(kwargs))

  @accepts_kwargs(COMMENT_FIELDS)
  def create_comment(self, **kwargs):
    return self.create('/comment', json.dumps(kwargs))

  @accepts_kwargs(DROP_FIELDS)
  def create_drop(self, **kwargs):
    return self.create('/drop', json.dumps(kwargs))

  @accepts_kwargs(FILE_FIELDS)
  def create_file(self, **kwargs):
    return self.create('/file', json.dumps(kwargs))

  @accepts_kwargs(GROUP_FIELDS)
  def create_group(self, **kwargs):
    return self.create('/group', json.dumps(kwargs))

  @accepts_kwargs(IDENTITY_FIELDS)
  def create_identity(self, **kwargs):
    return self.create('/identity', json.dumps(kwargs))

  @accepts_kwargs(TRACK_FIELDS)
  def create_track(self, **kwargs):
    return self.create('/track', json.dumps(kwargs))

  @accepts_kwargs(USER_FIELDS, 'defaultIdentity')
  def create_user(self, **kwargs):
    return self.create('/user', json.dumps(kwargs))

  @ensure_kwargs('id')
  @accepts_kwargs(APPLICATION_FIELDS, 'id')
  def update_application(self, **kwargs):
    return self.client.update(
        '/application/%s' % kwargs.pop('id'), json.dumps(kwargs))

  @ensure_kwargs('id')
  @accepts_kwargs(BUCKET_FIELDS, 'id')
  def update_bucket(self, **kwargs):
    return self.update(
        '/bucket/%s' % kwargs.pop('id'), json.dumps(kwargs))

  @ensure_kwargs('id')
  @accepts_kwargs(COMMENT_FIELDS, 'id')
  def update_comment(self, **kwargs):
    return self.update(
        '/comment/%s' % kwargs.pop('id'), json.dumps(kwargs))

  @ensure_kwargs('bucketId', 'id')
  @accepts_kwargs(DROP_FIELDS, 'id', 'bucketId')
  def update_drop(self, **kwargs):
    return self.update(
        '/drop/%s/%s' % (kwargs.pop('bucketId'), kwargs.pop('id')),
        json.dumps(kwargs))

  @ensure_kwargs('id')
  @accepts_kwargs(GROUP_FIELDS, 'id')
  def update_group(self, **kwargs):
    return self.update(
        '/group/%s' % kwargs.pop('id'), json.dumps(kwargs))

  @ensure_kwargs('id')
  @accepts_kwargs(IDENTITY_FIELDS, 'id')
  def update_identity(self, **kwargs):
    return self.update(
        '/identity/%s' % kwargs.pop('id'), json.dumps(kwargs))

  @ensure_kwargs('id')
  @accepts_kwargs(TRACK_FIELDS, 'id')
  def update_track(self, **kwargs):
    return self.update(
        '/track/%s' % kwargs.pop('id'), json.dumps(kwargs))

  @ensure_kwargs('id')
  @accepts_kwargs(USER_FIELDS, 'id')
  def update_user(self, **kwargs):
    return self.update(
        '/user/%s' % kwargs.pop('id'), json.dumps(kwargs))

  @ensure_kwargs('id')
  def delete_application(self, **kwargs):
    return self.delete('/application/%s' % kwargs.pop('id'))

  @ensure_kwargs('id')
  def delete_bucket(self, **kwargs):
    return self.delete('/bucket/%s' % kwargs.pop('id'))

  @ensure_kwargs('id')
  def delete_comment(self, **kwargs):
    return self.delete('/comment/%s' % kwargs.pop('id'))

  @ensure_kwargs('bucketId', 'id')
  def delete_drop(self, **kwargs):
    return self.delete('/drop/%s/%s' % (
      kwargs.pop('bucketId'), kwargs.pop('id')))

  @ensure_kwargs('id')
  def delete_file(self, **kwargs):
    return self.delete('/file/%s' % kwargs.pop('id'))

  @ensure_kwargs('id')
  def delete_group(self, **kwargs):
    return self.delete('/group/%s' % kwargs.pop('id'))

  @ensure_kwargs('id')
  def delete_identity(self, **kwargs):
    return self.delete('/identity/%s' % kwargs.pop('id'))

  @ensure_kwargs('id')
  def delete_track(self, **kwargs):
    return self.delete('/track/%s' % kwargs.pop('id'))

  @ensure_kwargs('id')
  def delete_user(self, **kwargs):
    return self.delete('/user/%s' % kwargs.pop('id'))

  @size_kwargs(1)
  @accepts_kwargs(['id', 'name'])
  def find_one_application(self, **kwargs):
    if 'name' in kwargs:
      params = {'criteria': json.dumps(kwargs), 'start': 0, 'limit': 1}
      return self.find_many('/application', params)[0]
    else:
      return self.find_one('/applcation/%s' % kwargs.pop('id'))

  @size_kwargs(1)
  @accepts_kwargs(['id', 'path'])
  def find_one_bucket(self, **kwargs):
    if 'path' in kwargs:
      params = {'criteria': json.dumps(kwargs), 'start': 0, 'limit': 1}
      return self.find_many('/bucket', params)[0]
    else:
      return self.find_one('/bucket/%s' % kwargs.pop('id'))

  @size_kwargs(1)
  @accepts_kwargs(['id'])
  def find_one_comment(self, **kwargs):
    return self.find_one('/comment/%s' % kwargs.pop('id'))

  @size_kwargs(2)
  @accepts_kwargs(['bucketId', 'id'])
  def find_one_drop(self, **kwargs):
    return self.find_one('/drop/%s/%s' % (
      kwargs.pop('bucketId'), kwargs.pop('id')))

  @size_kwargs(1)
  @accepts_kwargs(['id'])
  def find_one_file(self, **kwargs):
    return self.find_one('/file/%s' % kwargs.pop('id'))

  @size_kwargs(1)
  @accepts_kwargs(['id'])
  def find_one_group(self, **kwargs):
    return self.find_one('/group/%s' % kwargs.pop('id'))

  @size_kwargs(1)
  @accepts_kwargs(['id', 'alias'])
  def find_one_identity(self, **kwargs):
    if 'alias' in kwargs:
      params = {'criteria': json.dumps(kwargs), 'start': 0, 'limit': 1}
      return self.find_many('/identity', params)[0]
    else:
      return self.find_one('/identity/%s' % kwargs.pop('id'))

  @size_kwargs(1)
  @accepts_kwargs(['id'])
  def find_one_track(self, **kwargs):
    return self.find_one('/track/%s' % kwargs.pop('id'))
    pass

  @size_kwargs(1)
  @accepts_kwargs(['id', 'email'])
  def find_one_user(self, **kwargs):
    if 'email' in kwargs:
      params = {'criteria': json.dumps(kwargs), 'start': 0, 'limit': 1}
      return self.find_many('/user', params)[0]
    else:
      return self.find_one('/user/%s' % kwargs.pop('id'))

  @accepts_kwargs(APPLICATION_FIELDS, 'start', 'limit', 'sort', 'order')
  def find_many_applications(self, **kwargs):
    params = self._pop_pargs_from_kwargs(
        'start', 'limit', 'sort', 'order', **kwargs)
    params.update({'criteria': json.dumps(kwargs)})

    return self.find_many('/application', params)

  @accepts_kwargs(BUCKET_FIELDS, 'start', 'limit', 'sort', 'order')
  def find_many_buckets(self, **kwargs):
    params = self._pop_pargs_from_kwargs(
        'start', 'limit', 'sort', 'order', **kwargs)
    params.update({'criteria': json.dumps(kwargs)})

    return self.find_many('/bucket', params)

  @accepts_kwargs(COMMENT_FIELDS, 'start', 'limit', 'sort', 'order')
  def find_many_comments(self, **kwargs):
    params = self._pop_pargs_from_kwargs(
        'start', 'limit', 'sort', 'order', **kwargs)
    params.update({'criteria': json.dumps(kwargs)})

    return self.find_many('/comment', params)

  @ensure_kwargs('bucketId')
  @accepts_kwargs(DROP_FIELDS, 'start', 'limit', 'sort', 'order')
  def find_many_drops(self, **kwargs):
    bucket_id = kwargs.pop('bucketId')
    params = self._pop_pargs_from_kwargs(
        'start', 'limit', 'sort', 'order', **kwargs)
    params.update({'criteria': json.dumps(kwargs)})

    return self.find_many('/drop/%s' % bucket_id, params)

  @accepts_kwargs(GROUP_FIELDS, 'start', 'limit', 'sort', 'order')
  def find_many_groups(self, **kwargs):
    params = self._pop_pargs_from_kwargs(
        'start', 'limit', 'sort', 'order', **kwargs)
    params.update({'criteria': json.dumps(kwargs)})

    return self.find_many('/groups', params)

  @accepts_kwargs(IDENTITY_FIELDS, 'start', 'limit', 'sort', 'order')
  def find_many_identities(self, **kwargs):
    params = self._pop_pargs_from_kwargs(
        'start', 'limit', 'sort', 'order', **kwargs)
    params.update({'criteria': json.dumps(kwargs)})

    return self.find_many('/identity', params)

  @accepts_kwargs(TRACK_FIELDS, 'start', 'limit', 'sort', 'order')
  def find_many_tracks(self, **kwargs):
    params = self._pop_pargs_from_kwargs(
        'start', 'limit', 'sort', 'order', **kwargs)
    params.update({'criteria': json.dumps(kwargs)})

    return self.find_many('/track', params)

  @accepts_kwargs(USER_FIELDS, 'start', 'limit', 'sort', 'order')
  def find_many_users(self, **kwargs):
    params = self._pop_pargs_from_kwargs(
        'start', 'limit', 'sort', 'order', **kwargs)
    params.update({'criteria': json.dumps(kwargs)})

    return self.find_many('/user', params)

  @ensure_kwargs('query')
  @accepts_kwargs(['query', 'start', 'limit', 'sort', 'order'])
  def search_applications(self, **kwargs):
    return self.find_many('/application', kwargs)

  @ensure_kwargs('query')
  @accepts_kwargs(['query', 'start', 'limit', 'sort', 'order'])
  def search_buckets(self, **kwargs):
    return self.find_many('/bucket', kwargs)

  @ensure_kwargs('query')
  @accepts_kwargs(['query', 'start', 'limit', 'sort', 'order'])
  def search_comments(self, **kwargs):
    return self.find_many('/comment', kwargs)

  @ensure_kwargs('bucketId', 'query')
  @accepts_kwargs(['bucketId', 'query', 'start', 'limit', 'sort', 'order'])
  def search_drops(self, **kwargs):
    bucket_id = kwargs.pop('bucketId')
    return self.find_many('/drop/%s' % bucket_id, kwargs)

  @ensure_kwargs('query')
  @accepts_kwargs(['query', 'start', 'limit', 'sort', 'order'])
  def search_identities(self, **kwargs):
    return self.find_many('/identity', kwargs)

class ClientOpsException(Exception):
  def __init__(self, json_response):
    super(Exception, self).__init__()

if __name__ == '__main__':
  KEY     = sys.argv[1]
  SECRET  = sys.argv[2]
  ACTOR   = '000000000000000000000001'

  client = Client(KEY, SECRET, ACTOR)
  client.set_logger_file('ops_main.out')

  ops = ClientOps(client)

  lion_king = ops.create_application(
      name='lion_king',
      description='the lion king',
      email='simba@priderock.org',
      url='http://priderock.org')

  hakuna_matata = ops.create_application(
      name='hakuna_matata',
      description='songs from the lion king',
      email='simba@priderock.org',
      url='http://songs.priderock.org')

  ops.find_one_application(name='lion_king')
  ops.find_many_applications(email='simba@priderock.org')
  ops.search_applications(query='lion')

  ops.delete_application(id=lion_king['id'])
  ops.delete_application(id=hakuna_matata['id'])
