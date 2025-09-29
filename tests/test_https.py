from src import plugapi
import threading
import requests
import secrets
server = plugapi.Server(0, max_length_before_chunked=1024*1024, keyfile="tests/localhost-key.pem", certfile="tests/localhost.pem", https=True)

@server.handler("/", method=[plugapi.RequestMethod.GET, plugapi.RequestMethod.POST])
def index(request: plugapi.Request) -> plugapi.Response:
    if type(request.body) is bytes:
        return plugapi.TextResponse(request.body.decode(), 200)
    if type(request.body) is plugapi.ChunkStream:
        return plugapi.TextResponse(b"+".join(request.body).decode(), 200)
    return plugapi.TextResponse("Hello, World!", 200)

@server.handler(method=plugapi.RequestMethod.GET)
def custompath(request: plugapi.Request) -> plugapi.Response:
    return plugapi.JSONResponse(request.headers, 200)

@server.handler("/query_string", method=plugapi.RequestMethod.GET)
def query_string(request: plugapi.Request) -> plugapi.Response:
    return plugapi.JSONResponse(request.query, 200)

@server.handler(method=[plugapi.RequestMethod.GET, plugapi.RequestMethod.POST, plugapi.RequestMethod.PUT, plugapi.RequestMethod.DELETE, plugapi.RequestMethod.PATCH, plugapi.RequestMethod.HEAD, plugapi.RequestMethod.OPTIONS, plugapi.RequestMethod.TRACE, plugapi.RequestMethod.CONNECT])
def method(request: plugapi.Request) -> plugapi.Response:
    return plugapi.TextResponse(request.method.value, 200)

threading.Thread(target=server.run, daemon=True).start()
while server.port == 0:
    pass
print(f"Server running on port {server.port}")
def test_can_connect_https():
    try:
        res = requests.get(f"https://localhost:{server.port}", verify="tests/rootCA.pem")
        assert res.status_code == 200
        assert res.text == ""
    except:
        assert False, "Could not connect to server"

def test_headers_https():
    try:
        res = requests.get(f"https://localhost:{server.port}/custompath", headers={"X-Test-Header": "TestValue", "Host": f"localhost:{server.port}"}, verify="tests/rootCA.pem")
    except:
        assert False, "Could not connect to server"
    assert res.status_code == 200
    assert res.json() == dict(res.request.headers)

def test_404_https():
    try:
        res = requests.get(f"https://localhost:{server.port}/nonexistent", verify="tests/rootCA.pem")
    except:
        assert False, "Could not connect to server"
    assert res.status_code == 404
    assert res.text == "Not Found"

def test_query_string_https():
    try:
        res = requests.get(f"https://localhost:{server.port}/query_string?param1=value1&param2=value2&param2=value3&param3=%2B%3F%2A%2Btest%20abc", verify="tests/rootCA.pem")
    except:
        assert False, "Could not connect to server"
    assert res.status_code == 200
    assert res.json() == {"param1": ["value1"], "param2": ["value2", "value3"], "param3": ["+?*+test abc"]}

def test_chunk_https():
    try:
        res = requests.post(f"https://localhost:{server.port}", data=iter([b"chunk1", b"chunk2", b"chunk3"]), verify="tests/rootCA.pem")
    except:
        assert False, "Could not connect to server"
    assert res.status_code == 200
    assert res.text == "chunk1+chunk2+chunk3"

def test_get_https():
    try:
        res = requests.get(f"https://localhost:{server.port}/method", verify="tests/rootCA.pem")
    except:
        assert False, "Could not connect to server"
    assert res.status_code == 200
    assert res.text == "GET"

def test_post_https():
    try:
        res = requests.post(f"https://localhost:{server.port}/method", verify="tests/rootCA.pem")
    except:
        assert False, "Could not connect to server"
    assert res.status_code == 200
    assert res.text == "POST"    

def test_put_https():
    try:
        res = requests.put(f"https://localhost:{server.port}/method", verify="tests/rootCA.pem")
    except:
        assert False, "Could not connect to server"
    assert res.status_code == 200
    assert res.text == "PUT"

def test_delete_https():
    try:
        res = requests.delete(f"https://localhost:{server.port}/method", verify="tests/rootCA.pem")
    except:
        assert False, "Could not connect to server"
    assert res.status_code == 200
    assert res.text == "DELETE"

def test_patch_https():
    try:
        res = requests.patch(f"https://localhost:{server.port}/method", verify="tests/rootCA.pem")
    except:
        assert False, "Could not connect to server"
    assert res.status_code == 200
    assert res.text == "PATCH"

def test_head_https():
    try:
        res = requests.head(f"https://localhost:{server.port}/method", verify="tests/rootCA.pem")
    except:
        assert False, "Could not connect to server"
    assert res.status_code == 200
    assert res.text == ""

def test_options_https():
    try:
        res = requests.options(f"https://localhost:{server.port}/method", verify="tests/rootCA.pem")
    except:
        assert False, "Could not connect to server"
    assert res.status_code == 200
    assert res.text == "OPTIONS"

def test_trace_https():
    try:
        res = requests.request("TRACE", f"https://localhost:{server.port}/method", verify="tests/rootCA.pem")
    except:
        assert False, "Could not connect to server"
    assert res.status_code == 200
    assert res.text == "TRACE"

def test_connect_https():
    try:
        res = requests.request("CONNECT", f"https://localhost:{server.port}/method", verify="tests/rootCA.pem")
    except:
        assert False, "Could not connect to server"
    assert res.status_code == 200
    assert res.text == "CONNECT"

def test_large_file_https():
    large_data = secrets.token_hex(1024 * 1024) 
    try:
        res = requests.post(f"https://localhost:{server.port}", data=large_data, headers={"Content-Type": "application/octet-stream"}, verify="tests/rootCA.pem")
    except:
        assert False, "Could not connect to server"
    assert res.status_code == 200
    assert res.text == large_data[:1024*1024] + "+" + large_data[1024*1024:]
def test_chunked_large_file_https():
    x = ""
    def generate_large_data():
        nonlocal x
        for _ in range(512):
            to_add = secrets.token_hex(1024)
            x += to_add + "+"
            yield to_add.encode()  
    try:
        res = requests.post(f"https://localhost:{server.port}", data=generate_large_data(), headers={"Content-Type": "application/octet-stream", "Transfer-Encoding": "chunked"}, verify="tests/rootCA.pem")
    except:
        assert False, "Could not connect to server"
    assert res.status_code == 200
    x = x[:-1]
    assert res.text == x

