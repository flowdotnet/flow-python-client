The Flow Platform: Python Client Library
========================================

Usage
-----

    from flow import client

    api = client.API(YOUR_APP_KEY, YOUR_APP_SECRET)
    api.set_actor(ID_OF_IDENTITY_TO_DO_BUSINESS_AS)

Examples
--------

1. Turn type hinting off

    api.set_opts({'params': {'hints': 0}})

2. Retrieve a flow by its ID

    api.get('/bucket/%s' % ID)

3. Retrieve a flow by its path

    opts = {'params': {'criteria': """{"path": "%s"}""" % PATH}}
    api.get('/bucket', opts)

4. Retrieve the drops from a flow

    opts = {'params': {'start': OFFSET, 'limit': LIMIT}}
    api.get('/drop/%s' % BUCKET_ID, opts)

5. Retrive **all** the drops from a flow

    def get_drops(api, bucket_id, offset, limit):
      opts = {'params': {'start': offset, 'limit': limit}}
      results = json.loads(api.get('/drop/%s' % bucket_id, opts))

      if ('head' in results and
          'body' in results and
          'ok' in results['head'] and
          results['head']['ok'] and
          len(results['body']) > 0):
        return results['body']
      else:
        return []


    OFFSET = 0
    LIMIT = 500
    drops = []

    while True:
      more = get_drops(api, BUCKET_ID, OFFSET, LIMIT)

      if len(more) > 0:
        drops.extend(more)
        OFFSET += LIMIT
      else:
        break

6. Create a drop

    data = """
    { "path" : "%s"
    , "elems" :
      { "title" : { "type" : "string", "value" : "%s" }
      , "description" : { "type" : "string", "value" : "%s" }
      }
    }
    """ % (PATH, TITLE, DESCRIPTION)

    api.post('/drop', data)

7. Delete a drop

   api.delete('/drop/%s/%s' % (BUCKET_ID, ID))


Author / Maintainer
-------------------

Jeffrey Olchovy <jeff@flow.net>
