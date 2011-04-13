import os, sys, logging
import httplib, urllib, json
import time, hashlib

class API(object):
  URI     = 'api.flow.net'
  FS_URI  = 'fs.flow.net'
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
    self.logger = logging.getLogger('flow.client.API')
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

  def mk_cache_key(self, url, headers):
    filtered_headers = dict(filter(
      lambda x: x[0] != 'X-Timestamp' or x[0] != 'X-Signature',
      headers.items()))

    return '%s:%s' % (url, pickle.loads(filtered_headers))
  
  def mk_creds(self):
    headers = {
        'X-Actor': self.actor,
        'X-Key': self.key,
        'X-Timestamp' : self.mk_timestamp()}

    headers['X-Signature'] = self.mk_signature(headers)
    return headers

  def mk_timestamp(self):
    return str(int(time.time() * 1000))

  def mk_signature(self, creds):
    md = hashlib.sha1()

    for pair in sorted(creds.iteritems()):
      md.update(str(pair[0].lower()) + ':' + str(pair[1]))
    else:
      md.update(self.secret)

    return md.hexdigest()

  def mk_opts(self, opts):
    if 'headers' not in opts: opts['headers'] = {}
    if 'params' not in opts: opts['params'] = {}

    opts['headers'].update(self.opts['headers'])
    opts['params'].update(self.opts['params'])

    return opts

  def mk_headers(self, default, given):
    if given:
      headers = dict(default, **given)
    else:
      headers = default

    headers['User-Agent'] = 'flow-python-client_0.1A'
    return dict(headers, **self.mk_creds())

  def mk_url(self, base, params):
    if params:
      return '%s?%s' % (base, urllib.urlencode(params))
    else:
      return base

  def mk_request(self, url, method, data=None, opts={}):
    opts = self.mk_opts(opts)
    url = self.mk_url(url, opts['params'])
    headers = self.mk_headers(API.DEFAULT_HEADERS[method], opts['headers'])

    return self.request(url, method, data, headers)

  def request(self, url, method, data=None, headers={}):
    if self.cache is not None: 
      key = self.mk_cache_key(url, headers)
      cached = False

    else: cached = False

    if cached:
      self.logger.debug('-- Begin Cache Request --')
      self.logger.debug('KEY> %s\n' % key)
      self.logger.debug('VALUE> %s\n' % value)
      self.logger.debug('-- End Cache Request --\n')

    else:
      data = data.encode('utf-8') if data else None
      conn = httplib.HTTPConnection(API.URI + ':' + str(API.PORT))
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
    return self.mk_request(url, 'GET', None, opts)

  def post(self, url, data, opts={}):
    return self.mk_request(url, 'POST', data, opts)

  def put(self, url, data, opts={}):
    return self.mk_request(url, 'PUT', data, opts)

  def delete(self, url, opts={}):
    return self.mk_request(url, 'DELETE', None, opts)

  def oauth_uri(self, path, params=None):
    return 'http://%s/oauth%s%s' % (
        API.URI + ':' + str(API.PORT), path,
        '?' + urllib.urlencode(params) if params else '')
