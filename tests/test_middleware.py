from src import plugapi
import threading
import requests
import json
import base64
server = plugapi.Server(0, max_length_before_chunked=10)
server.add_middlewares(plugapi.json_middleware, plugapi.url_encoded_middleware, plugapi.multipart_middleware, plugapi.cors_middleware)
@server.handler("/", method=[plugapi.RequestMethod.GET, plugapi.RequestMethod.POST])
def index(request: plugapi.Request) -> plugapi.Response:
    if isinstance(request.body, dict):
        return plugapi.TextResponse(json.dumps(request.body), 200)
    return plugapi.TextResponse("Hello, World!", 200)

@server.handler(method=plugapi.RequestMethod.POST)
def url_encoded(request: plugapi.Request) -> plugapi.Response:
    if isinstance(request.body, dict):
        return plugapi.TextResponse(json.dumps(request.body), 200)
    return plugapi.TextResponse("Hello, World!", 200)

@server.handler(method=plugapi.RequestMethod.POST)
def multipart(request: plugapi.Request) -> plugapi.Response:
    if isinstance(request.body, dict):
        return plugapi.JSONResponse({key: [entry.type, base64.b64encode(entry.data).decode(), entry.file_name] for key in request.body if isinstance((entry := request.body[key]), plugapi.MultipartEntry)}, 200)
    return plugapi.TextResponse("Hello, World!", 200)
threading.Thread(target=server.run, daemon=True).start()
while server.port == 0:
    pass

def test_json_parsing():
    try:
        res = requests.post(f"http://localhost:{server.port}/", json={"key": "value"})
    except:
        assert False, "Could not connect to server"
    assert res.status_code == 200
    assert res.text == '{"key": "value"}'
def test_non_json_parsing():
    try:
        res = requests.post(f"http://localhost:{server.port}/", data="Just a plain text")
    except:
        assert False, "Could not connect to server"
    assert res.status_code == 200
    assert res.text == "Hello, World!"

def test_url_encoded_parsing():
    try:
        res = requests.post(f"http://localhost:{server.port}/", data={"key1": "value1%20?+&'\"", "key2": "value2"})
    except:
        assert False, "Could not connect to server"
    assert res.status_code == 200
    assert res.text == '{"key1": ["value1%20?+&\'\\""], "key2": ["value2"]}'

def test_multipart_parsing():
    try:
        res = requests.post(f"http://localhost:{server.port}/multipart", files={"file1": ("test.txt", b"Hello, World!", "text/plain"), "file2": ("image.png", b"\x89PNG\r\n\x1a\n", "image/png")}, data={"key": "value"})
    except:
        assert False, "Could not connect to server"
    assert res.status_code == 200
    assert res.text == '{"key": ["application/octet-stream", "dmFsdWU=", null], "file1": ["text/plain", "SGVsbG8sIFdvcmxkIQ==", "test.txt"], "file2": ["image/png", "iVBORw0KGgo=", "image.png"]}'

def test_cors_headers():
    try:
        res = requests.options(f"http://localhost:{server.port}/", headers={"Origin": "http://example.com", "Access-Control-Request-Method": "POST"})
    except:
        assert False, "Could not connect to server"
    assert res.status_code == 204
    assert res.headers.get("Access-Control-Allow-Origin") == "*"
    assert res.headers.get("Access-Control-Allow-Methods") == "*"
    assert res.headers.get("Access-Control-Allow-Headers") == "*"