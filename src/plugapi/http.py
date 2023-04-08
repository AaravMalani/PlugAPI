import io
import json
import socket
from threading import Thread, Lock, current_thread
import time
from enum import Enum as _Enum
from enum import auto
from dataclasses import dataclass, field
import mimetypes
import ssl
import traceback
from urllib.parse import parse_qs

"""
This file contains the HTTP server class and related classes
"""

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
class Response:
    """
    Class for creating a response to send to a client

    Attributes:
        body {str | list | dict | io.TextIOBase | io.BytesIO} -- The body of the response
        status {int} -- The status code of the response (default: {200})
        headers {dict[str, str]} -- The headers of the response (default: {})
    """
    body: str | list | dict | io.TextIOBase | io.BytesIO
    status: int = 200
    headers: dict[str, str] = field(default_factory=dict)

    def to_bytes(self) -> bytes:
        """
        Converts the response to bytes

        Returns:
            bytes: The response in bytes
        """
        self.headers['Content-Length'] = len(self.body)
        return f"HTTP/1.1 {self.status} {status_codes[self.status]}\r\n".encode() + "".join([f"{key}: {value}\r\n" for key, value in self.headers.items()]).encode() + b"\r\n" + (self.body.encode() if isinstance(self.body, str) else self.body)

    def send(self, client: socket.socket):
        """
        Sends the response to a client

        Arguments:
            client {`socket.socket`} -- The client to send the response to
        """
        client.send(self.to_bytes())


@dataclass
class JSONResponse(Response):
    """
    Class for creating a JSON response to send to a client

    Inherits from:
        Response -- The base response class

    Attributes:
        body {str | list | dict} -- The body of the response
    """

    def __post_init__(self):
        self.headers["Content-Type"] = "application/json"
        self.body = json.dumps(self.body)

@dataclass
class JSONPResponse(Response):
    """
    Class for creating a JSONP response to send to a client

    Inherits from:
        Response -- The base response class

    Attributes:
        body {str} -- The body of the response
        callback {str} -- The name of the callback function (default: {"callback"})
    """

    callback: str = "callback"

    def __post_init__(self):
        self.headers["Content-Type"] = "application/javascript"
        self.body = f"{self.callback}({json.dumps(self.body)})"


@dataclass
class HTMLResponse(Response):
    """
    Class for creating a HTML response to send to a client

    Inherits from:
        Response -- The base response class

    Attributes:
        body {str} -- The body of the response
    """

    def __post_init__(self):
        self.headers["Content-Type"] = "text/html"
        self.body = self.body.encode()


@dataclass
class FileResponse(Response):
    """
    Class for sending a file to a client

    Inherits from:
        Response -- The base response class

    Attributes:
        body {io.TextIOBase | io.BytesIO | str} -- The body of the response
        attachment {bool} -- Whether to display the file in the browser (inline) or as an attachment (default: {False (inline)})
        includeFilename {bool} -- Whether to include the filename in the Content-Disposition header (default: {True})
    """
    attachment: bool = False
    includeFilename: bool = True
    def __post_init__(self):
        if isinstance(self.body, str):
            with open(self.body, "rb") as file:
                name = file.name
                self.body = file.read()
        else:
            self.headers["Content-Type"] = mimetypes.guess_type(
                self.body.name)[0] or "application/octet-stream"
            name = self.body.name
            self.body = self.body.read()
        self.headers["Content-Disposition"] = ('attachment' if self.attachment else 'inline') + (('; filename='+name) if self.includeFilename else '')

@dataclass
class RedirectResponse(Response):
    """
    Class for creating a redirect response to send to a client

    Inherits from:
        Response -- The base response class

    Attributes:
        to {str} -- The URL to redirect to (default: {""} (due to dataclass limitations))
    """
    to : str = ""
    body : str = ""
    def __post_init__(self):
        if self.status not in range(300, 401):
            self.status = 308
        self.headers["Location"] = self.to
    



def parse_multipart(body: bytes, boundary: bytes) -> dict[str, str]:
    """
    Parses a multipart form

    Arguments:
        body {str} -- The body of the request
        boundary {str} -- The boundary of the multipart form

    Returns:
        dict[str, str] -- The parsed multipart form
    """
    form = {}
    for part in body.split(b"--"+boundary)[1:-1]:
        data = part.split(b"\r\n\r\n")
        headers = data[0].split(b"\r\n")[1:]
        parts = data[1:]

        type = b"application/octet-stream"
        name = None
        if headers[0].startswith(b"Content-Disposition"):
            name = headers[0].split(b";")[1].split(b"=")[1].strip(b'"')
            headers = headers[1:]   
        if headers[0].startswith(b"Content-Type"):
            type = headers[0].split(b":")[1].strip()
            headers = headers[1:]
        form[name.decode()] = {"type": type.decode(), "data": b"\r\n\r\n".join(parts)[:-2]}
    return form
def json_middleware(socket: socket.socket, method: str, headers: dict[str, str], body: str | list | dict) -> tuple[dict[str, str], str | list | dict]:
    """
    Middleware for parsing JSON

    Arguments:
        socket {socket.socket} -- The socket of the client
        method {str} -- The method of the request
        headers {dict[str, str]} -- The headers of the request
        body {str | list | dict} -- The body of the request

    Returns:
        tuple[dict[str, str], str | list | dict] -- The headers and body of the request
    """
    if headers.get("Content-Type", "").startswith("application/json"):
        body = json.loads(body)
    return headers, body

def cors_middleware(socket: socket.socket, method: str, headers: dict[str, str], body: str | list | dict) -> tuple[dict[str, str], str | list | dict]:
    """
    Middleware for adding CORS headers

    Arguments:
        socket {socket.socket} -- The socket of the client
        method {str} -- The method of the request
        headers {dict[str, str]} -- The headers of the request
        body {str | list | dict} -- The body of the request

    Returns:
        tuple[dict[str, str], str | list | dict] -- The headers and body of the request
    """
    headers["Access-Control-Allow-Origin"] = "*"
    headers["Access-Control-Allow-Headers"] = "*"
    headers["Access-Control-Allow-Methods"] = "*"
    return headers, body

def url_encoded_middleware(socket: socket.socket, method: str, headers: dict[str, str], body: str | list | dict) -> tuple[dict[str, str], str | list | dict]:
    """
    Middleware for parsing URL encoded data

    Arguments:
        socket {socket.socket} -- The socket of the client
        method {str} -- The method of the request
        headers {dict[str, str]} -- The headers of the request
        body {str | list | dict} -- The body of the request

    Returns:
        tuple[dict[str, str], str | list | dict] -- The headers and body of the request
    """
    if headers.get("Content-Type", "").startswith("application/x-www-form-urlencoded"):
        body = parse_qs(body)
    return headers, body

def multipart_middleware(socket: socket.socket, method: str, headers: dict[str, str], body: str | list | dict) -> tuple[dict[str, str], str | list | dict]:
    """
    Middleware for parsing multipart data

    Arguments:
        socket {socket.socket} -- The socket of the client
        method {str} -- The method of the request
        headers {dict[str, str]} -- The headers of the request
        body {str | list | dict} -- The body of the request

    Returns:
        tuple[dict[str, str], str | list | dict] -- The headers and body of the request
    """
    if headers.get("Content-Type", "").startswith("multipart/form-data"):
        boundary = headers.get("Content-Type").split("boundary=")[1].encode()
        body = parse_multipart(body.encode(), boundary)
        
    return headers, body

def cookie_middleware(socket: socket.socket, method: str, headers: dict[str, str], body: str | list | dict) -> tuple[dict[str, str], str | list | dict]:
    """
    Middleware for parsing cookies

    Arguments:
        socket {socket.socket} -- The socket of the client
        method {str} -- The method of the request
        headers {dict[str, str]} -- The headers of the request
        body {str | list | dict} -- The body of the request

    Returns:
        tuple[dict[str, str], str | list | dict] -- The headers and body of the request
    """
    if "Cookie" in headers:
        cookies = {}
        for cookie in headers["Cookie"].split(";"):
            name, value = cookie.split("=")
            cookies[name] = value
        headers["Cookie"] = cookies
    return headers, body

class AutoName(_Enum):
    """
    Class for creating an enum with the name of the enum as the value

    Inherits from:
        enum.Enum -- The base enum class

    Methods:
        _generate_next_value_ -- Generates the next value
    """
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


@dataclass
class Request:
    """
    Class containing the request data

    Attributes:
        path {str} -- The path of the request
        method {RequestMethod} -- The method of the request
        headers {dict[str, str]} -- The request headers
        body {str | list | dict} -- The body of the request (if any)
        query {dict[str, list[str]]} -- The query string at the end of the path
        params {dict[str, str]} -- The parameters in the path
        cookie {str | dict[str, str]} -- The cookie of the request (if any) (dict if parsed by cookie_middleware)
    """
    path: str
    method: RequestMethod
    headers: dict[str, str]
    body: str | list | dict
    query: dict[str, list[str]]
    params: dict[str, str]
    cookie: str | dict[str, str]
    

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
        middlewares {list[callable]} -- The middlewares for the requests
        context {ssl.SSLContext | None} -- The SSL context for HTTPS
        shouldLogErrors {bool} -- Whether the server should log errors to the console
    """

    def __init__(self, port: int, timeout: int = 5, host: str = "localhost", https: bool = False, certfile: str | None = None, keyfile: str | None = None, shouldLogErrors: bool = True):
        """
        Constructor for the Server class

        Arguments:
            port {int} -- The port of the server 
            timeout {int} -- The timeout before the server closes the connection (default: {5})
            host {str} -- The host of the server (default: {"localhost"}) 
            https {bool} -- Whether the server is using HTTPS (default: {False})
            certfile {str | None} -- The certificate file for HTTPS (default: {None})
            keyfile {str | None} -- The key file for HTTPS (default: {None})
            shouldLogErrors {bool} -- Whether the server should log errors to the console (default: {True})
        """
        self.host = host
        self.port = port
        self.timeout = timeout
        self.socket: socket.socket
        self.threads: list[Thread] = []
        self.lock: Lock = Lock()
        self.handlers: dict[RequestMethod, dict[str, callable]] = {
            RequestMethod.GET: {},
            RequestMethod.POST: {},
            RequestMethod.PUT: {},
            RequestMethod.DELETE: {},
            RequestMethod.OPTIONS: {},
            RequestMethod.HEAD: {},
            RequestMethod.TRACE: {},
            RequestMethod.CONNECT: {}
        }
        self.https = https
        self.certfile = certfile
        self.keyfile = keyfile
        self.middlewares: list[callable] = []
        self.context: ssl.SSLContext | None = None
        self.shouldLogErrors = shouldLogErrors

    def add_middlewares(self, *middlewares):
        """
        Adds middlewares to the server

        Arguments:
            *middlewares {callable} -- The middlewares to add
        """
        self.middlewares += middlewares

    def run(self):
        """
        Runs the server
        """
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((self.host, self.port))
        self.socket.listen(5)
        self.socket.settimeout(2)
        if self.https:
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

    def _conn_thread(self, client: socket.socket, address: tuple):
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
        time_without_data = time.time()
        encoded_request = b''
        while True:
            data = client.recv(1024)
            if not data:
                if time.time() - time_without_data > self.timeout:
                    Response("Request Timeout", 408).send(client)
                    return clean()
            else:
                time_without_data = time.time()
            encoded_request += data
            if b"\r\n\r\n" in encoded_request:
                break
        try:
            request = encoded_request.decode().split("\r\n\r\n")[0].split("\r\n")
            request_method, path, http = request[0].split(" ")
            if http != "HTTP/1.1":
                Response("HTTP Version Not Supported", 505).send(client)
                return clean()
            headers = {}
            for header in request[1:-2]:
                key, value = header.split(": ")
                headers[key] = value

            body = ""
            if request_method != "GET":
                if "Content-Length" not in headers:
                    client.setblocking(False)

                    body = encoded_request[encoded_request.find(b"\r\n\r\n") + 3:] + client.recv(1024)
                    client.setblocking(True)
                else:
                    body = encoded_request[encoded_request.find(b"\r\n\r\n") + 3:]
                    body += client.recv(int(headers["Content-Length"]) - len(body))
                body = body.decode() if isinstance(body, bytes) else body

            for middleware in self.middlewares:
                headers, body = middleware(client, request_method, headers, body)

            query = {}
            if "?" in path:
                path, query_string = path.split("?")
                for key, value in [q.split("=") for q in query_string.split("&")]:
                    if key in query:
                        query[key] += [value]
                    else:
                        query[key] = [value]
            
            if path in self.handlers.get(RequestMethod(request_method), {}):
                self.handlers[RequestMethod(request_method)][path](
                    Request(path, RequestMethod(request_method), headers, body, query, {}, headers.get("Cookie", ""))).send(client)
            else:
                path = path.split("/")
                k = False
                for i in self.handlers.get(RequestMethod(request_method), {}):
                    params = {}

                    i = i.split("/")
                    k = False
                    if len(i) != len(path):
                        continue
                    
                    for i_e, path_e in zip(i, path):
                        if i_e.startswith(":"):
                            params[i_e[1:]] = path_e
                            k = True
                        elif i_e != path_e:
                            break
                    if k:
                        try:
                            self.handlers[RequestMethod(request_method)]["/".join(i)](
                            Request(
                                path=path, 
                                method=RequestMethod(request_method), 
                                headers=headers, 
                                body=body, 
                                query=query, 
                                params=params, 
                                cookie=headers.get("Cookie", "")
                            )).send(client)
                        except Exception:
                            Response("Internal Server Error", 500).send(client)
                            traceback.print_exc()
                        break
                if not k:    
                    Response("Not Found", status=404).send(client)
        except Exception as e:
            Response("Malformed Request", 400).send(client)
            if self.shouldLogErrors:
                traceback.print_exc()
                    
        
        clean()

    def handler(self, path: str = None, method: RequestMethod | list[RequestMethod] = RequestMethod.GET) -> callable:
        """
        The decorator for the handlers

        Arguments:
            path {str} -- The path of the handler
            method {RequestMethod | list[RequestMethod]} -- The HTTP method the handler can receive (default: {RequestMethod.GET})

        Returns:
            callable -- The decorator
        """
        def wrapper(func: callable):
            for methd in (method if isinstance(method, list) else [method]):
                self.handlers[methd][path] = func
            return func
        return wrapper