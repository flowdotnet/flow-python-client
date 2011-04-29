APPLICATION_FIELDS = [
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

BUCKET_FIELDS = [
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

COMMENT_FIELDS = [
    'title',
    'description',
    'text',
    'bucketId',
    'dropId',
    'pid',
    'tpid']

DROP_FIELDS = [
    'path',
    'elems']

FILE_FIELDS = [
    'name',
    'mimeType',
    'contents']

GROUP_FIELDS = [
    'name',
    'displayName',
    'identities',
    'permissions',
    'identityPermissions']

IDENTITY_FIELDS = [
    'firstName',
    'lastName',
    'alias',
    'avatar',
    'groupIds',
    'userId',
    'appIds',
    'permissions']

TRACK_FIELDS = [
    'from',
    'to',
    'filterString',
    'transformFunction',
    'permissions']

USER_FIELDS = [
    'email',
    'password',
    'permissions']

def accepts_kwargs(valid_kws, *additional_valid_kws):
  def decorator(fn):
    def wrapped(self, **kwargs):
      valid_kws.extend(additional_valid_kws)
      valid_kwargs = dict(filter(
        lambda x: x[0] in valid_kws and x[1] is not None, 
        kwargs.items()))

      return fn(self, **valid_kwargs)
    return wrapped
  return decorator

def ensure_kwargs(*kws):
  def decorator(fn):
    def wrapped(self, **kwargs):
      missing_kws = [kw for kw in kws if kw not in kwargs]

      if len(missing_kws) > 0:
        raise Exception('Keyword arguments(%s) are required' % (
          ', '.join(missing_kws)))

      return fn(self, **kwargs)
    return wrapped
  return decorator

def size_kwargs(size):
  def decorator(fn):
    def wrapped(self, **kwargs):
      if len(kwargs) != size:
        raise Exception('Keyword arguments are limited to length %s' % (
          size))

      return fn(self, **kwargs)
    return wrapped
  return decorator
