PlugAPI : A lightweight, speedy HTTP(S) server
==============================================

Requirements
------------

-  Python 3.6 >=

Usage
-----

.. code:: py

   from plugapi import Server, JSONResponse, json_middleware

   server = Server(443, https=True, certfile='./localhost.pem', keyfile='./localhost-key.pem') 
   @server.handler(path='/')
   def root(req):
       return JSONResponse({'a': 'b'})

   
   server.add_middlewares(json_middleware)
   server.run()

--------

-  Middleware Middleware are functions accepting the request and the remaining middlewares and returning the response from the next middleware 
   or the handler if there are no more middlewares. You can add
   middlewares using ``server.add_middlewares(middleware, middleware2, ....)`` 
   For example, the default JSON middleware is given below

   .. code-block:: py

      def json_middleware(req: Request, next: MiddlewareType, handler: typing.Callable[[Request], Response]) -> Response:
         """
         Middleware for parsing JSON

         Arguments:
            req: {Request} -- The request object
            next {MiddlewareType} -- The remaining middlewares
            handler {typing.Callable[[Request], Response]} -- The handler function

         Returns:
            Response -- The response object
         """

         if req.headers.get("Content-Type", "").startswith("application/json"):
            if isinstance(req.body, ChunkStream):
                  req.body = b"".join(req.body)
            if isinstance(req.body, bytes):
                  req.body = json.loads(req.body)
         if len(next):
            return next[0](req, next[1:], handler)
         return handler(req)
         
   There are numerous built-in middlewares including
   ``multipart_middleware``, ``url_encoded_middleware``,
   ``cookie_middleware`` and more!
-  Different utility responses Responses like ``FileResponse``,
   ``JSONResponse`` and ``HTMLResponse`` are pre-provided to allow you
   to return data without having to set the content type

To-Do
-----

-  ☐ Websocket support
-  ☑ Parameters in paths
