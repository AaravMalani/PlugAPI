Changelog
=========

Version 1.1
-----------

Added ``multipart_middleware``, ``url_encoded_middleware``,
``cors_middleware``

Version 1.2
-----------

-  Added URL params (``/:id/:uuid`` for example)
-  Added ``attachment`` and ``includeFilename`` in ``FileResponse``
-  Added ``RedirectResponse`` and ``JSONPResponse``
-  Changed ``RequestType`` to ``RequestMethod`` and made name changes as
   such
-  Added error handling for rogue malformed requests
-  Added documentation

Version 1.2.1
-------------

Fixed a bug where ``/`` would not work

Version 1.2.2
-------------

Fixed a bug completely breaking the server 
(Replaced ``None.startswith with`` ``"".startswith`` for default ``Content-Type``
 and passed empty params and cookies to the ``Request`` constructor)