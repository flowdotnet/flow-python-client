import unittest
import logging
import flow

KEY     = '4e5ff8640943c37e3bb49bd3' 
SECRET  = 'KtgPGKyrVN'
ACTOR   = '000000000000000000000001'

example_application = flow.Application(
    name = 'flow_python_client_example_application',
    email = 'jeff@flow.net')

example_bucket_1 = flow.Flow(
    name = 'flow_python_client_example_bucket_1',
    path = '/test/flow_python_client_example_bucket_1')

example_bucket_2 = flow.Flow(
    name = 'flow_python_client_example_bucket_2',
    path = '/test/flow_python_client_example_bucket_2')

example_bucket_3 = flow.Flow(
    name = 'flow_python_client_example_bucket_3',
    path = '/test/flow_python_client_example_bucket_3')

example_bucket_4 = flow.Flow(
    name = 'flow_python_client_example_bucket_4',
    path = '/test/flow_python_client_example_bucket_4')

example_bucket_5 = flow.Flow(
    name = 'flow_python_client_example_bucket_5',
    path = '/test/flow_python_client_example_bucket_5')

example_comment = flow.Comment(
    text = 'Lorem ipsum dolor sit amet')

example_drop = flow.Drop(
    elems = {
      'foo': {'type': 'string', 'value': 'Lorem ipsum dolor sit amet'},
      'bar': {'type': 'integer', 'value': 12}
    })

example_file = flow.File()

example_group = flow.Group()

example_identity = flow.Identity()

example_track = flow.Track(**{
  'from': example_bucket_4.path,
  'to': example_bucket_5.path})

example_user = flow.User(
  email = 'jeff@flow.net',
  password = 'j3ff@f10w.n37')

class MarshalerTestCase(unittest.TestCase):
  DUMPABLE = [
      example_application,
      example_bucket_1,
      example_bucket_2,
      example_bucket_3,
      example_bucket_4,
      example_bucket_5,
      example_comment,
      example_drop,
      example_file,
      example_group,
      example_identity,
      example_track,
      example_user]

  LOADABLE = []

  def setUp(self):
    self.marshaler = None

  def test_dumps(self):
    if self.marshaler:
      for i in self.__class__.DUMPABLE:
        print self.marshaler.dumps(i)

  def test_loads(self):
    if self.marshaler:
      for i in self.__class__.LOADABLE:
        self.marshaler.loads(i)

class JsonMarshalerTestCase(MarshalerTestCase):
  LOADABLE = [
  """
  { "type" : "application"
  , "value" :
    {
    }
  }
  """,

  """
  { "type" : "flow"
  , "value" : 
    {
    }
  }
  """,

  """
  { "type" : "comment"
  , "value" : 
    {
    }
  }
  """,

  """
  { "type" : "drop"
  , "value" :
    {
    }
  }
  """,

  """
  { "type" : "file"
  , "value" : 
    {
    }
  }
  """,

  """
  { "type" : "group"
  , "value" :
    {
    }
  }
  """,

  """
  { "type" : "identity"
  , "value" :
    {
    }
  }
  """,

  """
  { "type" : "track"
  , "value" : 
    {
    }
  }
  """,

  """
  { "type" : "user"
  , "value" : 
    {
    }
  }
  """]

  def setUp(self):
    self.marshaler = flow.JsonMarshaler()

class XmlMarshalerTestCase(MarshalerTestCase):
  LOADABLE = [
  """
  <application type="application">
  </application>
  """,

  """
  <bucket type="flow">
  </bucket>
  """,

  """
  <comment type="comment">
  </comment>
  """,

  """
  <drop type="drop">
  </drop>
  """,

  """
  <file type="file">
  </file>
  """,

  """
  <group type="group">
  </group>
  """,

  """
  <identity type="identity">
  </identity>
  """,

  """
  <track type="track">
  </track>
  """,

  """
  <user type="user">
  </user>
  """]

  def setUp(self):
    self.marshaler = flow.XmlMarshaler()

class RestClientTestCase(unittest.TestCase):
  def setUp(self):
    self.client = flow.RestClient(KEY, SECRET, ACTOR)
    self.client.set_logger_file('RestClientTestCase.log')
    self.client.set_logger_level(logging.DEBUG)

class JsonRestClientTestCase(RestClientTestCase):
  def setUp(self):
    self.client = flow.JsonRestClient(KEY, SECRET, ACTOR)
    self.client.set_logger_file('JsonRestClientTestCase.log')
    self.client.set_logger_level(logging.DEBUG)

class XmlRestClientTestCase(RestClientTestCase):
  def setUp(self):
    self.client = flow.XmlRestClient(KEY, SECRET, ACTOR)
    self.client.set_logger_file('XmlRestClientTestCase.log')
    self.client.set_logger_level(logging.DEBUG)

class DomainObjectTestCase(unittest.TestCase):
  def setUp(self):
    self.domain_object = None
    self.saved = False
    self.deleted = False

  def tearDown(self): 
    if self.saved and not self.deleted:
      self.ensureDelete()

  def ensureDelete(self):
    if self.domain_object and self.domain_object.id:
      rest_client = flow.RestClient(KEY, SECRET, ACTOR)
      rest_client.http_delete(
          self.domain_object.__class__.instance_bound_path(
            self.domain_object.get_uid()))

  def runTest(self):
    if self.domain_object and self.client:
      self.save()
      self.find()
      self.delete()

  def save(self):
    self.domain_object.save(self.client)
    self.saved = True

  def find(self):
    self.domain_object.find(self.client, id=self.domain_object.id)

  def delete(self):
    self.domain_object.delete(self.client)
    self.deleted = True

class ApplicationTestCase(DomainObjectTestCase):
  def setUp(self):
    super(ApplicationTestCase, self).setUp()
    #self.domain_object = example_application

class JsonApplicationTestCase(ApplicationTestCase, JsonRestClientTestCase):
  def setUp(self):
    JsonRestClientTestCase.setUp(self)
    ApplicationTestCase.setUp(self)

class XmlApplicationTestCase(ApplicationTestCase, XmlRestClientTestCase):
  def setUp(self):
    XmlRestClientTestCase.setUp(self)
    ApplicationTestCase.setUp(self)

class FlowTestCase(DomainObjectTestCase):
  def setUp(self):
    super(FlowTestCase, self).setUp()
    #self.domain_object = example_bucket_1

class JsonFlowTestCase(FlowTestCase, JsonRestClientTestCase):
  def setUp(self):
    JsonRestClientTestCase.setUp(self)
    FlowTestCase.setUp(self)

class XmlFlowTestCase(FlowTestCase, XmlRestClientTestCase):
  def setUp(self):
    XmlRestClientTestCase.setUp(self)
    FlowTestCase.setUp(self)

class CommentTestCase(DomainObjectTestCase):
  def setUp(self):
    super(CommentTestCase, self).setUp()
    #self.domain_object = flow.Comment()

class JsonCommentTestCase(CommentTestCase, JsonRestClientTestCase):
  def setUp(self):
    JsonRestClientTestCase.setUp(self)
    CommentTestCase.setUp(self)

class XmlCommentTestCase(CommentTestCase, XmlRestClientTestCase):
  def setUp(self):
    XmlRestClientTestCase.setUp(self)
    CommentTestCase.setUp(self)

class DropTestCase(DomainObjectTestCase):
  def setUp(self):
    super(DropTestCase, self).setUp()
    #self.domain_object = flow.Drop()

class JsonDropTestCase(DropTestCase, JsonRestClientTestCase):
  def setUp(self):
    JsonRestClientTestCase.setUp(self)
    DropTestCase.setUp(self)
    
class XmlDropTestCase(DropTestCase, XmlRestClientTestCase):
  def setUp(self):
    XmlRestClientTestCase.setUp(self)
    DropTestCase.setUp(self)

class FileTestCase(DomainObjectTestCase):
  def setUp(self):
    super(FileTestCase, self).setUp()
    #self.domain_object = flow.File()

class JsonFileTestCase(FileTestCase, JsonRestClientTestCase):
  def setUp(self):
    JsonRestClientTestCase.setUp(self)
    FileTestCase.setUp(self)

class XmlFileTestCase(FileTestCase, XmlRestClientTestCase):
  def setUp(self):
    XmlRestClientTestCase.setUp(self)
    FileTestCase.setUp(self)

class GroupTestCase(DomainObjectTestCase):
  def setUp(self):
    super(GroupTestCase, self).setUp()
    #self.domain_object = flow.Group()

class JsonGroupTestCase(GroupTestCase, JsonRestClientTestCase):
  def setUp(self):
    JsonRestClientTestCase.setUp(self)
    GroupTestCase.setUp(self)

class XmlGroupTestCase(GroupTestCase, XmlRestClientTestCase):
  def setUp(self):
    XmlRestClientTestCase.setUp(self)
    GroupTestCase.setUp(self)

class IdentityTestCase(DomainObjectTestCase):
  def setUp(self):
    super(IdentityTestCase, self).setUp()
    #self.domain_object = flow.Identity()

class JsonIdentityTestCase(IdentityTestCase, JsonRestClientTestCase):
  def setUp(self):
    JsonRestClientTestCase.setUp(self)
    IdentityTestCase.setUp(self)

class XmlIdentityTestCase(IdentityTestCase, XmlRestClientTestCase):
  def setUp(self):
    XmlRestClientTestCase.setUp(self)
    IdentityTestCase.setUp(self)

class TrackTestCase(DomainObjectTestCase):
  def setUp(self):
    super(TrackTestCase, self).setUp()
    #self.domain_object = flow.Track()

class JsonTrackTestCase(TrackTestCase, JsonRestClientTestCase):
  def setUp(self):
    JsonRestClientTestCase.setUp(self)
    TrackTestCase.setUp(self)

class XmlTrackTestCase(TrackTestCase, XmlRestClientTestCase):
  def setUp(self):
    XmlRestClientTestCase.setUp(self)
    TrackTestCase.setUp(self)

class UserTestCase(DomainObjectTestCase):
  def setUp(self):
    super(UserTestCase, self).setUp()
    #self.domain_object = flow.User()

class JsonUserTestCase(UserTestCase, JsonRestClientTestCase):
  def setUp(self):
    JsonRestClientTestCase.setUp(self)
    UserTestCase.setUp(self)

class XmlUserTestCase(UserTestCase, XmlRestClientTestCase):
  def setUp(self):
    XmlRestClientTestCase.setUp(self)
    UserTestCase.setUp(self)

if __name__ == '__main__':
  unittest.main()
