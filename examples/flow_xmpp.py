import flow
import logging
import xml.dom.minidom

class ExampleXmppClient(flow.XmppClient):
  def __init__(self, jid, key, secret, actor, *pargs):
    super(ExampleXmppClient, self).__init__(jid, key, secret, actor)
    self.subscription_ids = list(pargs)

  def authenticate_callback(self):
    self.stream.send('<presence to="pubsub.xmpp.flow.net" from="%s"/>' % self.jid.full())

    for i, id in enumerate(self.subscription_ids):
      subscription = [
        '<iq type="set" to="pubsub.xmpp.flow.net" from="%s" id="sub-%s">' % (self.jid.full(), i),
          '<query xmlns="flow:pubsub">',
            '<subscribe flow="%s"/>' % id,
          '</query>'
        '</iq>']

      self.stream.send(''.join(subscription))

  def incoming_packet_callback(self, buf):
    stanza = xml.dom.minidom.parseString(buf)

    if stanza.getElementsByTagName('ping'):
      self._handle_ping(stanza)

    if stanza.getElementsByTagName('drop'):
      self._handle_drop(stanza)

  def _handle_ping(self, node):
    pong = [
      '<iq type="set" to="pubsub.xmpp.flow.net" from="%s" id="pong">' % self.jid.full(),
        '<query xmlns="flow:pubsub">',
          '<pong/>',
        '</query>',
      '</iq>']

    self.stream.send(''.join(pong))

  def _handle_drop(self, node):
    self.logger.debug('Drop reception event')

if __name__ == '__main__':
  jid     = '' # app name # identity alias @ xmpp.flow.net
  key     = '' # app key
  secret  = '' # app secret
  actor   = '' # identity id
  flows   = [] # flow ids

  client = ExampleXmppClient(jid, key, secret, actor, *flows)
  client.set_logger_file('flow_xmpp.log')
  client.set_logger_level(logging.DEBUG)
  client.start()
