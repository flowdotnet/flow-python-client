import unittest
from flow import client

class APITest(unittest.TestCase):
  def test(self):
    api = client.API('key', 'secret')
    print 'ok'

if __name__ == '__main__':
  unittest.main()
