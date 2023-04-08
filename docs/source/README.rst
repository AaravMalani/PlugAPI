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

Features
--------

-  Middleware Middleware are functions accepting the socket, HTTP type,
   headers and body and returning a changed headers and body before the
   handlers are called They can be added using
   ``server.add_middlewares(middleware, middleware2, ....)`` For
   example, the default JSON middleware is given below

   .. code-block:: py

     def json_middleware(socket: socket.socket, type: str, headers: dict[str, str], body: str | list | dict) -> tuple[dict[str, str], str | list | dict]:
          if headers.get("Content-Type", None) == "application/json":             
          body = json.loads(body)         
          return headers, body``
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
