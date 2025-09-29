from src import plugapi
import threading
import requests
import secrets
server = plugapi.Server(0, max_length_before_chunked=1024*1024)

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
def test_can_connect():
    try:
        res = requests.get(f"http://localhost:{server.port}")
        assert res.status_code == 200
        assert res.text == ""
    except:
        assert False, "Could not connect to server"

def test_headers():
    try:
        res = requests.get(f"http://localhost:{server.port}/custompath", headers={"X-Test-Header": "TestValue", "Host": f"localhost:{server.port}"})
    except:
        assert False, "Could not connect to server"
    assert res.status_code == 200
    assert res.json() == dict(res.request.headers)

def test_404():
    try:
        res = requests.get(f"http://localhost:{server.port}/nonexistent")
    except:
        assert False, "Could not connect to server"
    assert res.status_code == 404
    assert res.text == "Not Found"

def test_query_string():
    try:
        res = requests.get(f"http://localhost:{server.port}/query_string?param1=value1&param2=value2&param2=value3&param3=%2B%3F%2A%2Btest%20abc")
    except:
        assert False, "Could not connect to server"
    assert res.status_code == 200
    assert res.json() == {"param1": ["value1"], "param2": ["value2", "value3"], "param3": ["+?*+test abc"]}

def test_chunk():
    try:
        res = requests.post(f"http://localhost:{server.port}", data=iter([b"chunk1", b"chunk2", b"chunk3"]))
    except:
        assert False, "Could not connect to server"
    assert res.status_code == 200
    assert res.text == "chunk1+chunk2+chunk3"

def test_get():
    try:
        res = requests.get(f"http://localhost:{server.port}/method")
    except:
        assert False, "Could not connect to server"
    assert res.status_code == 200
    assert res.text == "GET"

def test_post():
    try:
        res = requests.post(f"http://localhost:{server.port}/method")
    except:
        assert False, "Could not connect to server"
    assert res.status_code == 200
    assert res.text == "POST"    

def test_put():
    try:
        res = requests.put(f"http://localhost:{server.port}/method")
    except:
        assert False, "Could not connect to server"
    assert res.status_code == 200
    assert res.text == "PUT"

def test_delete():
    try:
        res = requests.delete(f"http://localhost:{server.port}/method")
    except:
        assert False, "Could not connect to server"
    assert res.status_code == 200
    assert res.text == "DELETE"

def test_patch():
    try:
        res = requests.patch(f"http://localhost:{server.port}/method")
    except:
        assert False, "Could not connect to server"
    assert res.status_code == 200
    assert res.text == "PATCH"

def test_head():
    try:
        res = requests.head(f"http://localhost:{server.port}/method")
    except:
        assert False, "Could not connect to server"
    assert res.status_code == 200
    assert res.text == ""

def test_options():
    try:
        res = requests.options(f"http://localhost:{server.port}/method")
    except:
        assert False, "Could not connect to server"
    assert res.status_code == 200
    assert res.text == "OPTIONS"

def test_trace():
    try:
        res = requests.request("TRACE", f"http://localhost:{server.port}/method")
    except:
        assert False, "Could not connect to server"
    assert res.status_code == 200
    assert res.text == "TRACE"

def test_connect():
    try:
        res = requests.request("CONNECT", f"http://localhost:{server.port}/method")
    except:
        assert False, "Could not connect to server"
    assert res.status_code == 200
    assert res.text == "CONNECT"

def test_large_file():
    large_data = secrets.token_hex(1024 * 1024) 
    try:
        res = requests.post(f"http://localhost:{server.port}", data=large_data, headers={"Content-Type": "application/octet-stream"})
    except:
        assert False, "Could not connect to server"
    assert res.status_code == 200
    assert res.text == large_data[:1024*1024] + "+" + large_data[1024*1024:]
def test_chunked_large_file():
    x = ""
    def generate_large_data():
        nonlocal x
        for _ in range(512):
            to_add = secrets.token_hex(1024)
            x += to_add + "+"
            yield to_add.encode()  
    try:
        res = requests.post(f"http://localhost:{server.port}", data=generate_large_data(), headers={"Content-Type": "application/octet-stream", "Transfer-Encoding": "chunked"})
    except:
        assert False, "Could not connect to server"
    assert res.status_code == 200
    x = x[:-1]
    assert res.text == x

