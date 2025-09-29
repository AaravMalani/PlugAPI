from src import plugapi
import threading
import requests
server = plugapi.Server(0, max_length_before_chunked=1024*1024)

@server.handler("/", method=[plugapi.RequestMethod.GET, plugapi.RequestMethod.POST])
def index(request: plugapi.Request) -> plugapi.Response:
    return plugapi.TextResponse("Hello, World!", 200)

@server.handler("/this/is/a/super/duper/long/path/that/just/keeps/going/on/and/on/and/on", method=plugapi.RequestMethod.GET)
def longpath(request: plugapi.Request) -> plugapi.Response:
    return plugapi.TextResponse("This is a long path!", 200)

@server.handler("/this/:is/a/:path", method=plugapi.RequestMethod.GET)
def path(request: plugapi.Request) -> plugapi.Response:
    return plugapi.JSONResponse(request.params, 200)

@server.handler("/this/:is/a/:path", method=plugapi.RequestMethod.POST)
def path_post(request: plugapi.Request) -> plugapi.Response:
    return plugapi.JSONResponse(request.params, 200, headers={"X-Test-Header": "POST"})

@server.handler("/path/with/:special_characters", method=plugapi.RequestMethod.GET)
def special_characters(request: plugapi.Request) -> plugapi.Response:
    return plugapi.JSONResponse(request.params, 200)

threading.Thread(target=server.run, daemon=True).start()
while server.port == 0:
    pass
print(f"Server running on port {server.port}")

def test_root_path():
    try:
        res = requests.get(f"http://localhost:{server.port}/")
    except:
        assert False, "Could not connect to server"
    assert res.status_code == 200
    assert res.text == "Hello, World!"

def test_long_path():
    try:
        res = requests.get(f"http://localhost:{server.port}/this/is/a/super/duper/long/path/that/just/keeps/going/on/and/on/and/on")
    except:
        assert False, "Could not connect to server"
    assert res.status_code == 200
    assert res.text == "This is a long path!"

def test_long_path_with_trailing_slash():
    try:
        res = requests.get(f"http://localhost:{server.port}/this/is/a/super/duper/long/path/that/just/keeps/going/on/and/on/and/on/")
    except:
        assert False, "Could not connect to server"
    assert res.status_code == 200
    assert res.text == "This is a long path!"

def test_path_get():
    try:
        res = requests.get(f"http://localhost:{server.port}/this/value1/a/value2")
    except:
        assert False, "Could not connect to server"
    assert res.status_code == 200
    assert res.json() == {"is": "value1", "path": "value2"}

def test_path_post():
    try:
        res = requests.post(f"http://localhost:{server.port}/this/value1/a/value2")
    except:
        assert False, "Could not connect to server"
    assert res.status_code == 200
    assert res.json() == {"is": "value1", "path": "value2"}
    assert res.headers.get("X-Test-Header") == "POST"


def test_path_special_characters_encoded():
    try:
        res = requests.get(f"http://localhost:{server.port}/path/with/value-._~%21%24%26%27%28%29%2A%2B%2C%3B%3D%3A%40")
    except:
        assert False, "Could not connect to server"
    assert res.status_code == 200
    assert res.json() == {"special_characters": "value-._~!$&'()*+,;=:@"}
