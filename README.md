The Flow Platform: Python Client Library
========================================

Usage
-----

    <pre>
    from flow import client

    api = client.API(YOUR_APP_KEY, YOUR_APP_SECRET)
    api.set_actor(ID_OF_IDENTITY_TO_DO_BUSINESS_AS)
    </pre>

Examples
--------

1. Turn type hinting off

    <pre>
    api.set_opts({&#39;params&#39;: {&#39;hints&#39;: 0}})
    </pre>

2. Retrieve a flow by its ID

    <pre>
    api.get(&#39;/bucket/%s&#39; % ID)
    </pre>

3. Retrieve a flow by its path

    <pre>
    opts = {&#39;params&#39;: {&#39;criteria&#39;: """{"path": "%s"}""" % PATH}}
    api.get(&#39;/bucket&#39;, opts)
    </pre>

4. Retrieve the drops from a flow

    <pre>
    opts = {&#39;params&#39;: {&#39;start&#39;: OFFSET, &#39;limit&#39;: LIMIT}}
    api.get(&#39;/drop/%s&#39; % BUCKET_ID, opts)
    </pre>

5. Retrive **all** the drops from a flow

    <pre>
    def get_drops(api, bucket_id, offset, limit):
      opts = {&#39;params&#39;: {&#39;start&#39;: offset, &#39;limit&#39;: limit}}
      results = json.loads(api.get(&#39;/drop/%s&#39; % bucket_id, opts))

      if (&#39;head&#39; in results and
          &#39;body&#39; in results and
          &#39;ok&#39; in results[&#39;head&#39;] and
          results[&#39;head&#39;][&#39;ok&#39;] and
          len(results[&#39;body&#39;]) > 0):
        return results[&#39;body&#39;]
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
    </pre>

6. Create a drop

    <pre>
    data = """
    { "path" : "%s"
    , "elems" :
      { "title" : { "type" : "string", "value" : "%s" }
      , "description" : { "type" : "string", "value" : "%s" }
      }
    }
    """ % (PATH, TITLE, DESCRIPTION)

    api.post(&#39;/drop&#39;, data)
    </pre>

7. Delete a drop

    <pre>
    api.delete(&#39;/drop/%s/%s&#39; % (BUCKET_ID, ID))
    </pre>


Author / Maintainer
-------------------

Jeffrey Olchovy <jeff@flow.net>
