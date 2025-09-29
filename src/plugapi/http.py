from __future__ import annotations
import io
import json
import socket
from threading import Thread, Lock, current_thread
import time
from enum import Enum as _Enum
from enum import auto
from dataclasses import dataclass
import mimetypes
import ssl
import traceback
import typing
from urllib.parse import parse_qs, unquote
import os.path

"""
This file contains the HTTP server class and related classes
"""

T = typing.TypeVar('T')

# Status messages from status codes
status_codes = {
    100: "Continue",
    101: "Switching Protocols",
    102: "Processing",
    103: "Early Hints",
    200: "OK",
    201: "Created",
    202: "Accepted",
    203: "Non-Authoritative Information",
    204: "No Content",
    205: "Reset Content",
    206: "Partial Content",
    207: "Multi-Status",
    208: "Already Reported",
    226: "IM Used",
    300: "Multiple Choices",
    301: "Moved Permanently",
    302: "Found",
    303: "See Other",
    304: "Not Modified",
    305: "Use Proxy",
    306: "Switch Proxy",
    307: "Temporary Redirect",
    308: "Permanent Redirect",
    400: "Bad Request",
    401: "Unauthorized",
    402: "Payment Required",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    406: "Not Acceptable",
    407: "Proxy Authentication Required",
    408: "Request Timeout",
    409: "Conflict",
    410: "Gone",
    411: "Length Required",
    412: "Precondition Failed",
    413: "Payload Too Large",
    414: "URI Too Long",
    415: "Unsupported Media Type",
    416: "Range Not Satisfiable",
    417: "Expectation Failed",
    418: "I'm a teapot",
    421: "Misdirected Request",
    422: "Unprocessable Entity",
    423: "Locked",
    424: "Failed Dependency",
    425: "Too Early",
    426: "Upgrade Required",
    428: "Precondition Required",
    429: "Too Many Requests",
    431: "Request Header Fields Too Large",
    451: "Unavailable For Legal Reasons",
    500: "Internal Server Error",
    501: "Not Implemented",
    502: "Bad Gateway",
    503: "Service Unavailable",
    504: "Gateway Timeout",
    505: "HTTP Version Not Supported",
    506: "Variant Also Negotiates",
    507: "Insufficient Storage",
    508: "Loop Detected",
    510: "Not Extended",
    511: "Network Authentication Required"
}


@dataclass
class Request:
    """
    Class containing the request data

    Attributes:
        path {str} -- The path of the request
        method {RequestMethod} -- The method of the request
        headers {dict[str, str]} -- The request headers
        body {str | list[str] | dict[str, MultipartEntry] | dict[str, list[str]] | ChunkStream[bytes] | ChunkStream[tuple[bytes, int]]} -- The body of the request (if any)
        query {dict[str, list[str]]} -- The query string at the end of the path
        params {dict[str, str]} -- The parameters in the path
        cookie {str | dict[str, str]} -- The cookie of the request (if any) (dict if parsed by cookie_middleware)
    """
    path: str
    method: RequestMethod
    headers: dict[str, str]
    body: bytes | list[str] | dict[str,
                                 MultipartEntry] | dict[str, list[str]] | ChunkStream[bytes] | ChunkStream[tuple[bytes, int]]
    query: dict[str, list[str]]
    params: dict[str, str]
    cookie: str | dict[str, str]


class Response:
    """
    Class for creating a response to send to a client

    Attributes:
        status {int} -- The status code of the response (default: {200})
        headers {dict[str, str]} -- The headers of the response (default: {})
    """
    status: int 
    headers: dict[str, str]
    _body_decoded: bytes 

    def to_bytes(self) -> bytes:
        """
        Converts the response to bytes

        Returns:
            bytes: The response in bytes
        """
        self.headers['Content-Length'] = str(len(self._body_decoded))
        return f"HTTP/1.1 {self.status} {status_codes[self.status]}\r\n".encode("utf-8") + "".join([f"{key}: {value}\r\n" for key, value in self.headers.items()]).encode("utf-8") + b"\r\n" + self._body_decoded

    def send(self, client: socket.socket):
        """
        Sends the response to a client

        Arguments:
            client {`socket.socket`} -- The client to send the response to
        """
        client.send(self.to_bytes())


HandlerType = typing.Callable[[Request], Response]
JSONType = typing.Mapping[str, 'JSONType'] | typing.Sequence['JSONType'] | str | int | float | bool | None
MiddlewareType = typing.Callable[[
    Request, list['MiddlewareType'], HandlerType], Response]

class TextResponse(Response):
    """
    Class for creating a text response to send to a client

    Inherits from:
        Response -- The base response class

    Attributes:
        body {str} -- The body of the response
    """
    body: str
    def __init__(self, body: str = "", status: int = 200, headers: dict[str, str] = {}):
        """
        Initializes the TextResponse class

        Arguments:
            body {str} -- The body of the response (default: {""})
            status {int} -- The status code of the response (default: {200})
            headers {dict[str, str]} -- The headers of the response (default: {{}})
        """
        self.body = body
        self.status = status
        self.headers = headers
        self.headers["Content-Type"] = "text/plain"
        self._body_decoded = self.body.encode("utf-8")
    
class JSONResponse(Response):
    """
    Class for creating a JSON response to send to a client

    Inherits from:
        Response -- The base response class

    Attributes:
        body {JSONType} -- The body of the response
    """
    body: JSONType = {}
    def __init__(self, body: JSONType = {}, status: int = 200, headers: dict[str, str] = {}):
        """
        Initializes the JSONResponse class

        Arguments:
            body {JSONType} -- The body of the response (default: {{}})
            status {int} -- The status code of the response (default: {200})
            headers {dict[str, str]} -- The headers of the response (default: {{}})
        """
        self.body = body
        self.status = status
        self.headers = headers
        self.headers["Content-Type"] = "application/json"
        self._body_decoded = json.dumps(self.body).encode("utf-8")


class JSONPResponse(Response):
    """
    Class for creating a JSONP response to send to a client

    Inherits from:
        Response -- The base response class

    Attributes:
        body {JSONType} -- The body of the response
        callback {str} -- The name of the callback function (default: {"callback"})
    """

    body: JSONType
    callback: str 

    def __init__(self, body: JSONType = {}, callback: str = "callback", status: int = 200, headers: dict[str, str] = {}):
        """
        Initializes the JSONPResponse class
        Arguments:
            body {JSONType} -- The body of the response (default: {{}})
            callback {str} -- The name of the callback function (default: {"callback"})
            status {int} -- The status code of the response (default: {200})
            headers {dict[str, str]} -- The headers of the response (default: {{}})
        """
        self.body = body
        self.callback = callback
        self.status = status
        self.headers = headers
        self.headers["Content-Type"] = "application/javascript"
        self._body_decoded = f"{self.callback}({json.dumps(self.body)});".encode("utf-8")


@dataclass
class HTMLResponse(Response):
    """
    Class for creating a HTML response to send to a client

    Inherits from:
        Response -- The base response class

    Attributes:
        body {str} -- The body of the response
    """

    def __init__(self, body: str = "", status: int = 200, headers: dict[str, str] = {}):
        """
        Initializes the HTMLResponse class

        Arguments:
            body {str} -- The body of the response (default: {""})
            status {int} -- The status code of the response (default: {200})
            headers {dict[str, str]} -- The headers of the response (default: {{}})
        """
        self.body = body
        self.status = status
        self.headers = headers
        self.headers["Content-Type"] = "text/html"
        self._body_decoded = self.body.encode("utf-8")

class FileResponse(Response):
    """
    Class for sending a file to a client

    Inherits from:
        Response -- The base response class

    Attributes:
        body {io.BufferedReader | str} -- The body of the response
        attachment {bool} -- Whether to display the file in the browser (inline) or as an attachment (default: {False (inline)})
        includeFilename {bool} -- Whether to include the filename in the Content-Disposition header (default: {True})
        filename {str | None} -- The filename to include in the Content-Disposition header (default: {None})
    """
    body: io.BufferedReader | str 
    attachment: bool = False
    includeFilename: bool = True
    filename: str | None = None

    def __init__(self, body: io.BufferedReader | str = "", attachment: bool = False, includeFilename: bool = True, filename: str | None = None, status: int = 200, headers: dict[str, str] = {}):
        """
        Initializes the FileResponse class
        Arguments:
            body {io.BufferedReader | str} -- The body of the response (default: {""})
            attachment {bool} -- Whether to display the file in the browser (inline) or as an attachment (default: {False (inline)})
            includeFilename {bool} -- Whether to include the filename in the Content-Disposition header (default: {True})
            filename {str | None} -- The filename to include in the Content-Disposition header (default: {None})
            status {int} -- The status code of the response (default: {200})
            headers {dict[str, str]} -- The headers of the response (default: {{}})
        """
        
        self.body = body
        self.attachment = attachment
        self.includeFilename = includeFilename
        self.status = status
        self.headers = headers
        self.filename = filename if includeFilename else None
        if isinstance(self.body, str):
            with open(self.body, "rb") as file:
                if self.includeFilename and not self.filename:
                    self.filename = file.name
                self._body_decoded = file.read()
            self.headers["Content-Type"] = mimetypes.guess_type(
                self.body)[0] or "application/octet-stream"
        else:
            self.headers["Content-Type"] = mimetypes.guess_type(
                self.body.name)[0] or "application/octet-stream"
            self._body_decoded = self.body.read()
        self.filename = os.path.basename(self.filename) if self.filename else None
        self.headers["Content-Disposition"] = ('attachment' if self.attachment else 'inline') + (
            ('; filename="'+self.filename+'"') if self.filename else '')


class RedirectResponse(Response):
    """
    Class for creating a redirect response to send to a client

    Inherits from:
        Response -- The base response class

    Attributes:
        to {str} -- The URL to redirect to
    """
    to: str 

    def __init__(self, to: str = "/", status: int = 308, headers: dict[str, str] = {}):
        """
        Initializes the RedirectResponse class
        Arguments:
            to {str} -- The URL to redirect to (default: {"/"})
            status {int} -- The status code of the response (default: {308})
            headers {dict[str, str]} -- The headers of the response (default: {{}})
        """
        self.to = to
        self.status = status
        self.headers = headers
        if self.status not in range(300, 401):
            self.status = 308
        self.headers["Location"] = self.to
        self._body_decoded = b""  

@dataclass
class MultipartEntry:
    """
    Class for creating a multipart entry

    Attributes:
        type {str} -- The content type of the entry (default: {"application/octet-stream"})
        data {bytes} -- The data of the entry
    """

    type: str = "application/octet-stream"
    data: bytes = b""
    file_name: str | None = None


def parse_multipart(body: bytes, boundary: bytes) -> dict[str, MultipartEntry]:
    """
    Parses a multipart form

    Arguments:
        body {str} -- The body of the request
        boundary {str} -- The boundary of the multipart form

    Returns:
        dict[str, MultipartEntry] -- The parsed multipart form
    """
    form: dict[str, MultipartEntry] = {}
    for part in body.split(b"--"+boundary)[1:-1]:
        data = part.split(b"\r\n\r\n")
        headers = data[0].split(b"\r\n")[1:]
        parts = data[1:]

        type = b"application/octet-stream"
        name = b""
        filename = None
        for header in headers:
                
            if header.startswith(b"Content-Disposition"):
                directives: dict[bytes, bytes] = {}
                for i in header.split(b";"):
                    if b"=" in i:
                        key = i.split(b"=")[0].strip()
                        value = i.split(b"=", 1)[1].strip(b'"')
                        directives[key] = value
                if b"name" in directives:
                    name = directives[b"name"]
                if b"filename" in directives:
                    filename = directives[b"filename"]
                
            if header.startswith(b"Content-Type"):
                type = header.split(b":")[1].strip()
        if name:
            form[name.decode("utf-8")] = MultipartEntry(
                type=type.decode("utf-8"), data=b"\r\n\r\n".join(parts)[:-2], file_name=filename.decode("utf-8") if filename else None)

    return form




def json_middleware(req: Request, next: list[MiddlewareType], handler: HandlerType) -> Response:
    """
    Middleware for parsing JSON

    Arguments:
        req: {Request} -- The request object
        next {list[MiddlewareType]} -- The remaining middlewares
        handler {HandlerType} -- The handler function

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


def cors_middleware(req: Request, next: list[MiddlewareType], handler: HandlerType) -> Response:
    """
    Middleware for adding CORS headers

    Arguments:
        req: {Request} -- The request object
        next {list[MiddlewareType]} -- The remaining middlewares
        handler {HandlerType} -- The handler function

    Returns:
        Response -- The response object
    """
    if len(next):
        res = next[0](req, next[1:], handler)
    else:
        res = handler(req)
    res.headers["Access-Control-Allow-Origin"] = "*"
    res.headers["Access-Control-Allow-Headers"] = "*"
    res.headers["Access-Control-Allow-Methods"] = "*"
    return res


def url_encoded_middleware(req: Request, next: list[MiddlewareType], handler: HandlerType) -> Response:
    """
    Middleware for parsing URL encoded data

    Arguments:
        req: {Request} -- The request object
        next {list[MiddlewareType]} -- The remaining middlewares
        handler {HandlerType} -- The handler function

    Returns:
        Response -- The response object
    """
    if req.headers.get("Content-Type", "").startswith("application/x-www-form-urlencoded"):
        if isinstance(req.body, ChunkStream):
            req.body = b"".join(req.body)
        if isinstance(req.body, bytes):
            req.body = parse_qs(req.body.decode("utf-8"), encoding="utf-8")
    if len(next):
        return next[0](req, next[1:], handler)
    return handler(req)


def multipart_middleware(req: Request, next: list[MiddlewareType], handler: HandlerType) -> Response:
    """
    Middleware for parsing multipart data

    Arguments:
        req: {Request} -- The request object
        next {list[MiddlewareType]} -- The remaining middlewares
        handler {HandlerType} -- The handler function

    Returns:
        Response -- The response object
    """
    if req.headers.get("Content-Type", "").startswith("multipart/form-data"):
        if isinstance(req.body, ChunkStream):
            req.body = b"".join(req.body)
        if isinstance(req.body, bytes):
            boundary = req.headers.get(
                "Content-Type", "").split("boundary=")[1].encode("utf-8")
            req.body = parse_multipart(req.body, boundary)

    if len(next):
        return next[0](req, next[1:], handler)
    return handler(req)


def cookie_middleware(req: Request, next: list[MiddlewareType], handler: HandlerType) -> Response:
    """
    Middleware for parsing cookies

    Arguments:
        req: {Request} -- The request object
        next {list[MiddlewareType]} -- The remaining middlewares
        handler {HandlerType} -- The handler function

    Returns:
        Response -- The response object
    """
    if "Cookie" in req.headers:
        cookies = {}
        for cookie in req.headers["Cookie"].split(";"):
            name, value = cookie.split("=")
            cookies[name] = value
        req.cookie = cookies
    if len(next):
        return next[0](req, next[1:], handler)
    return handler(req)


class AutoName(_Enum):
    """
    Class for creating an enum with the name of the enum as the value

    Inherits from:
        enum.Enum -- The base enum class

    Methods:
        _generate_next_value_ -- Generates the next value
    """
    @staticmethod
    def _generate_next_value_(name: str, start: int, count: int, last_values: list[str]) -> str:
        """
        Generates the next value of the enum as the name of the enum value

        Arguments:
            name {str} -- The name of the enum value
            start {int} -- The start of the enum (unused)
            count {int} -- The count of the enum (unused)
            last_values {list[str]} -- The last values of the enum (unused)
        """
        return name


class RequestMethod(AutoName):
    """
    The enum containing HTTP request methods

    Inherits from:
        AutoName -- The base enum class
    """
    GET = auto()
    POST = auto()
    PUT = auto()
    DELETE = auto()
    OPTIONS = auto()
    HEAD = auto()
    TRACE = auto()
    CONNECT = auto()
    PATCH = auto()


class ChunkStream(typing.Generic[T]):
    """
    Class for creating a chunked stream

    Attributes:
        func {typing.Callable[[T], typing.Tuple[T, bytes]]} -- The function to call to get the next chunk
        value {T} -- The value to pass to the function
    """
    def __init__(self, func: typing.Callable[[T], typing.Tuple[T, bytes]], initial_value: T):
        """
        Initializes the ChunkStream class

        Arguments:
            func {typing.Callable[[T], typing.Tuple[T, bytes]]} -- The function to call to get the next chunk
            initial_value {T} -- The initial value to pass to the function
        """
        self.func = func
        self.value = initial_value

    def __iter__(self):
        return self

    def __next__(self) -> bytes:
        self.value, to_return = self.func(self.value)
        return to_return


class Server:
    """
    Class for creating a HTTP(S) server

    Attributes:
        host {str} -- The host of the server
        port {int} -- The port of the server
        timeout {int} -- The timeout before the server closes the connection 
        socket {socket.socket} -- The socket of the server
        threads {list[Thread]} -- The connection threads
        lock {Lock} -- The lock for the threads list
        handlers {dict[RequestMethod, dict[str, callable]]} -- The handlers for the requests
        https {bool} -- Whether the server is using HTTPS
        certfile {str | None} -- The certificate file for HTTPS
        keyfile {str | None} -- The key file for HTTPS
        middlewares {list[MiddlewareType]} -- The middlewares for the requests
        context {ssl.SSLContext | None} -- The SSL context for HTTPS
        should_log_errors {bool} -- Whether the server should log errors to the console
        max_length_before_chunked {int} -- The maximum Content-Length before the body is returned as a ChunkStream
        max_header_size {int} -- The maximum size of the headers in bytes (default: {8192})
    """

    def __init__(self, port: int, timeout: int = 5, host: str = "localhost", https: bool = False, certfile: str | None = None, keyfile: str | None = None, should_log_errors: bool = True, max_length_before_chunked: int = 536870912, max_header_size: int = 8192):
        """
        Constructor for the Server class

        Arguments:
            port {int} -- The port of the server 
            timeout {int} -- The timeout before the server closes the connection (default: {5})
            host {str} -- The host of the server (default: {"localhost"}) 
            https {bool} -- Whether the server is using HTTPS (default: {False})
            certfile {str | None} -- The certificate file for HTTPS (default: {None})
            keyfile {str | None} -- The key file for HTTPS (default: {None})
            should_log_errors {bool} -- Whether the server should log errors to the console (default: {True})
            max_length_before_chunked {int} -- The maximum Content-Length before the body is returned as a ChunkStream (default: {536870912})
            max_header_size {int} -- The maximum size of the headers in bytes (default: {8192})
        """
        self.host = host
        self.port = port
        self.timeout = timeout
        self.socket: socket.socket
        self.threads: list[Thread] = []
        self.lock: Lock = Lock()
        self.handlers: dict[RequestMethod, dict[str, HandlerType]] = {
            RequestMethod.GET: {},
            RequestMethod.POST: {},
            RequestMethod.PUT: {},
            RequestMethod.PATCH: {},
            RequestMethod.DELETE: {},
            RequestMethod.OPTIONS: {},
            RequestMethod.HEAD: {},
            RequestMethod.TRACE: {},
            RequestMethod.CONNECT: {}
        }
        self.https = https
        self.certfile = certfile
        self.keyfile = keyfile
        self.middlewares: list[MiddlewareType] = []
        self.context: ssl.SSLContext | None = None
        self.should_log_errors = should_log_errors
        self.max_length_before_chunked = max_length_before_chunked
        self.max_header_size = max_header_size

    def add_middlewares(self, *middlewares: MiddlewareType):
        """
        Adds middlewares to the server

        Arguments:
            *middlewares {MiddlewareType} -- The middlewares to add
        """
        self.middlewares += middlewares

    def run(self):
        """
        Runs the server
        """
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((self.host, self.port))
        self.port = self.socket.getsockname()[1]
        self.socket.listen(5)
        self.socket.settimeout(2)
        if self.https and self.certfile and self.keyfile:
            self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.context.load_cert_chain(
                certfile=self.certfile, keyfile=self.keyfile)
            self.socket = self.context.wrap_socket(
                self.socket, server_side=True)
        while True:
            try:
                sock = self.socket.accept()
            except socket.timeout:
                continue

            thread = Thread(target=self._conn_thread, args=sock)
            thread.daemon = True
            self.lock.acquire()
            self.threads += [thread]
            self.lock.release()
            thread.start()

    def find_handler(self, request_method: str, path: str) -> typing.Optional[tuple[HandlerType, dict[str, str]]]:
        """
        Finds the handler for a request
        Arguments:
            request_method {str} -- The method of the request
            path {str} -- The path of the request

        Returns:
            tuple[HandlerType, dict[str, str]] | None -- The handler and the parameters in the path (if any)
        """
        if path.endswith("/") and path != "/":
            path = path[:-1]
        if path in self.handlers.get(RequestMethod(request_method), {}):
            return self.handlers[RequestMethod(request_method)][path], {}

        path_split = path.split("/")
        k = False
        for i in self.handlers.get(RequestMethod(request_method), {}):
            params: dict[str, str] = {}

            i = i.split("/")
            k = True
            if len(i) != len(path_split):
                continue
            
            for i_e, path_e in zip(i, path_split):
                if i_e.startswith(":"):
                    params[i_e[1:]] = unquote(path_e)
                elif i_e != path_e:
                    k = False
                    break
            if k:
                return self.handlers[RequestMethod(request_method)]["/".join(i)], params

    def option_handler(self, path: str) -> HandlerType:
        """
        The handler for OPTIONS requests

        Arguments:
            path {str} -- The path of the handler

        Returns:
            HandlerType -- The handler
        """

        def wrapper(req: Request) -> Response:
            allowed_methods = [method.name for method in self.handlers if self.find_handler(method.name, path)]
            return TextResponse("", 204, headers={"Allow": ", ".join(allowed_methods)})
        return wrapper
    def _conn_thread(self, client: socket.socket, address: tuple[str, int]):
        """
        The thread for the connection

        Arguments:
            client {socket.socket} -- The client socket
            address {tuple} -- The address of the client
        """
        def clean():
            self.lock.acquire()
            self.threads.remove(current_thread())
            self.lock.release()
            client.close()
        try: 
            builder = RequestBuilder(client, self)
            req = builder.build()
            if not req:
                return clean()
            handler_params = self.find_handler(req.method.value, req.path)
            if not handler_params:
                if req.method != RequestMethod.OPTIONS:
                        
                    TextResponse("Not Found", status=404).send(client)
                    return clean()
                handler_params = (self.option_handler(req.path), dict[str, str]())
            handler, params = handler_params
            req.params = params
        
        except Exception:
            if self.should_log_errors:
                traceback.print_exc()
            return TextResponse("Malformed Request", 400).send(client)

        try:
            if self.middlewares:
                self.middlewares[0](
                    req, self.middlewares[1:], handler).send(client)
            else:
                handler(req).send(client)
        except Exception:
            if self.should_log_errors:
                traceback.print_exc()
            TextResponse("Internal Server Error", 500).send(client)
        clean()

    def handler(self, path: str | None = None, method: RequestMethod | list[RequestMethod] = RequestMethod.GET) -> typing.Callable[[HandlerType], HandlerType]:
        """
        The decorator for the handlers

        Arguments:
            path {str} -- The path of the handler
            method {RequestMethod | list[RequestMethod]} -- The HTTP method the handler can receive (default: {RequestMethod.GET})

        Returns:
            callable -- The decorator
        """

        def wrapper(func: HandlerType) -> HandlerType:
            nonlocal path
            path = path or "/"+func.__name__
            for methd in (method if isinstance(method, list) else [method]):
                self.handlers[methd][path] = func
            return func
        return wrapper


class RequestBuilder:
    """
    Class for building a request from a client socket
    Attributes:
        client {socket.socket} -- The client socket
        server {Server} -- The server instance
    """
    def __init__(self, client: socket.socket, server: Server):
        """
        Initializes the RequestBuilder class
        Arguments:
            client {socket.socket} -- The client socket
            server {Server} -- The server instance
        """
        self.client = client
        self.server = server

    def receive_request(self) -> typing.Optional[bytes]:
        """
        Receives the request headers from the client
        """
        time_without_data = time.time()
        encoded_request = b''
        while b"\r\n\r\n" not in encoded_request:
            if len(encoded_request) > self.server.max_header_size:
                return TextResponse("Request Header Fields Too Large", 431).send(self.client)
            data = self.client.recv(1024)
            if not data:
                if time.time() - time_without_data > self.server.timeout:
                    return TextResponse("Request Timeout", 408).send(self.client)
            else:
                time_without_data = time.time()
            encoded_request += data
        return encoded_request

    def parse_method_path(self, raw_request: bytes) -> typing.Optional[tuple[str, str]]:
        """
        Parses the request method and path from the raw request
        Arguments:
            raw_request {bytes} -- The raw request from the client
        """
        request = raw_request.split(b"\r\n\r\n", 1)[
            0].split(b"\r\n", 1)
        request_method, path, http = request[0].split(b" ")
        if http != b"HTTP/1.1":
            return TextResponse("HTTP Version Not Supported", 505).send(self.client)
        return request_method.decode("utf-8"), path.decode("utf-8")

    def parse_headers(self, raw_request: bytes) -> typing.Optional[dict[str, str]]:
        """
        Parses the headers from the raw request
        Arguments:
            raw_request {bytes} -- The raw request from the client
        """
        request = raw_request.split(b"\r\n\r\n", 1)[
            0].split(b"\r\n")
        headers: dict[str, str] = {}
        for header in request[1:]:
            key, value = header.split(b": ")
            headers[key.decode("utf-8")] = value.decode("utf-8")
        return headers

    def parse_query(self, path: str) -> tuple[str, dict[str, list[str]]]:
        """
        Parses the query string from the path
        Arguments:
            path {str} -- The path of the request
        """
        query: dict[str, list[str]] = {}
        if "?" in path:
            path, query_string = path.split("?")
            query = parse_qs(query_string, encoding="utf-8")
            
        return path, query

    def content_length_stream_func(self, data: tuple[bytes, int]) -> tuple[tuple[bytes, int], bytes]:
        """
        The function for streaming a body with a Content-Length header greater than max_length_before_chunked
        Arguments:
            data {tuple[bytes, int]} -- The current state of the stream (encoded_request, length)

        Returns:
            tuple[tuple[bytes, int], bytes] -- The new state of the stream and the next chunk
        """
        encoded_request, length = data
        if length == 0:
            raise StopIteration
        to_return_length = min(
            length, self.server.max_length_before_chunked)
        to_return = encoded_request[:to_return_length]
        encoded_request = encoded_request[to_return_length:]
        while len(to_return) != to_return_length:
            to_return += self.client.recv(
                to_return_length - len(to_return))
            
        length -= to_return_length
        return (encoded_request, length), to_return

    def chunked_stream_func(self, encoded_request: bytes) -> tuple[bytes, bytes]:
        """
        The function for streaming a body with a Transfer-Encoding: chunked header
        Arguments:
            encoded_request {bytes} -- The current state of the stream (encoded_request)
        
        Returns:
            tuple[bytes, bytes] -- The new state of the stream and the next chunk
        """
        while b"\r\n" not in encoded_request:
            encoded_request += self.client.recv(200)
        length = int(encoded_request.split(b"\r\n")[0], 16)
        if length == 0:
            raise StopIteration
        try:
            encoded_request = encoded_request.split(b"\r\n", 1)[1]
        except IndexError:
            raise
        length += 2
        while (length - len(encoded_request)) > 0:
            encoded_request += self.client.recv(
                length - len(encoded_request))
        to_return = encoded_request[:length-2]
        encoded_request = encoded_request[length:]
        return (encoded_request, to_return)

    def parse_body(self, encoded_request: bytes, headers: dict[str, str]) -> typing.Optional[bytes | ChunkStream[tuple[bytes, int]] | ChunkStream[bytes]]:
        """
        Parses the body from the raw request
        Arguments:
            encoded_request {bytes} -- The raw request from the client
            headers {dict[str, str]} -- The headers of the request
        """
        if "Content-Length" in headers:
            if int(headers["Content-Length"]) > self.server.max_length_before_chunked:
                length = int(headers["Content-Length"])
                return ChunkStream(self.content_length_stream_func, (encoded_request, length))
            body = encoded_request[:int(headers["Content-Length"])]
            while len(body) != int(headers["Content-Length"]):
                body += self.client.recv(
                    int(headers["Content-Length"]) - len(body))
            return body
        elif "Transfer-Encoding" in headers and headers["Transfer-Encoding"] == "chunked":
            return ChunkStream(self.chunked_stream_func, encoded_request)
        else:
            return b""
        
    def build(self) -> Request | None:
        """
        Builds the request from the client socket
        Returns:
            Request | None -- The built request or None if the request is malformed
        """
        encoded_request = self.receive_request()
        if not encoded_request:
            return
        request_method_path = self.parse_method_path(encoded_request)
        if not request_method_path:
            return
        request_method, path = request_method_path
        headers = self.parse_headers(encoded_request)
        if not headers:
            return

        body = b""
        encoded_request = encoded_request[encoded_request.find(
            b"\r\n\r\n") + 4:]
        if request_method != "TRACE":
            body = self.parse_body(encoded_request, headers)
            if body is None:
                return

        path, query = self.parse_query(path)
        return Request(
            path,
            method=RequestMethod(request_method),
            headers=headers,
            body=body,
            query=query,
            params={},
            cookie=headers.get("Cookie", "")
        )
