import random
import typing
from src import plugapi
import threading
import requests
import json
from urllib.parse import quote
import pytest
server = plugapi.Server(0)

JSONType = typing.Mapping[str, 'JSONType'] | typing.Sequence['JSONType'] | str | int | float | bool | None
lst = tuple(chr(i) for i in range(32, 0x110000) if chr(i).isprintable())
def random_json_generator() -> JSONType:
    x = random.randint(1, 6)
    if x == 1:
        return {''.join(random.choices(lst, k=random.randint(1, 100))): random_json_generator() for _ in range(random.randint(1, 5))}
    elif x == 2:
        return [random_json_generator() for _ in range(random.randint(1, 5))]
    elif x == 3:
        return random.randint(-10**18, 10**18)
    elif x == 4:
        return random.uniform(-10**18, 10**18)
    elif x == 5:
        return random.choice([True, False])
    return None

@server.handler("/json", method=[plugapi.RequestMethod.GET])
def index(request: plugapi.Request) -> plugapi.Response:
    if isinstance(request.body, bytes):
        return plugapi.JSONResponse(json.loads(request.body), 200)
    return plugapi.TextResponse("Hello, World!", 200)

@server.handler("/jsonp", method=[plugapi.RequestMethod.GET])
def jsonp(request: plugapi.Request) -> plugapi.Response:
    if isinstance(request.body, bytes):
        return plugapi.JSONPResponse(json.loads(request.body), callback=request.query["callback"][0], status=200)
    return plugapi.TextResponse("Hello, World!", 200)

@server.handler("/file", method=[plugapi.RequestMethod.GET])
def file_response(request: plugapi.Request) -> plugapi.Response:
    return plugapi.FileResponse("tests/test_responses.py", attachment=request.query.get("download") == ["true"], status=200)
    
@server.handler("/file/bytes", method=[plugapi.RequestMethod.GET])
def file_response_bytes(request: plugapi.Request) -> plugapi.Response:
    with open("tests/test_responses.py", "rb") as f:
        return plugapi.FileResponse(f, filename="test_responses.py", status=200)

@server.handler("/html", method=plugapi.RequestMethod.GET)
def html_response(request: plugapi.Request) -> plugapi.Response:
    return plugapi.HTMLResponse("<html></html>")

@server.handler("/redir", method=plugapi.RequestMethod.GET)
def redirect_response(request: plugapi.Request) -> plugapi.Response:
    return plugapi.RedirectResponse("/")

threading.Thread(target=server.run, daemon=True).start()
while server.port == 0:
    pass

@pytest.mark.parametrize('execution_number', range(100))
def test_json_response(execution_number: int):
    try:
        test_json = random_json_generator()
    except RecursionError:
        test_json = {}
    if test_json is None:
        test_json: JSONType = {}
    try:
        res = requests.get(f"http://localhost:{server.port}/json", json=test_json)
    except:
        assert False, "Could not connect to server"
    assert res.status_code == 200
    assert res.headers["Content-Type"] == "application/json"
    assert res.json() == test_json

@pytest.mark.parametrize('execution_number', range(100))
def test_jsonp_response(execution_number: int):
    try:
        test_json = random_json_generator()
    except RecursionError:
        test_json = {}
    if test_json is None:
        test_json: JSONType = {}
    callback_name = ''.join(random.choices(lst, k=random.randint(1, 20)))
    try:

        res = requests.get(f"http://localhost:{server.port}/jsonp?callback={quote(callback_name, encoding="utf-8")}", json=test_json)
    except:
        assert False, "Could not connect to server"
    assert res.status_code == 200
    assert res.headers["Content-Type"] == "application/javascript"
    assert res.content == callback_name.encode("utf-8") + b"(" + json.dumps(test_json).encode("utf-8") + b");"

def test_file_response():
    try:
        res = requests.get(f"http://localhost:{server.port}/file")
    except:
        assert False, "Could not connect to server"
    assert res.status_code == 200
    assert res.headers["Content-Type"] == "text/x-python"
    with open("tests/test_responses.py", "rb") as f:
        assert res.content == f.read()
    assert res.headers["Content-Disposition"] == 'inline; filename="test_responses.py"'

def test_file_response_attachment():
    try:
        res = requests.get(f"http://localhost:{server.port}/file?download=true")
    except:
        assert False, "Could not connect to server"
    assert res.status_code == 200
    assert res.headers["Content-Type"] == "text/x-python"
    with open("tests/test_responses.py", "rb") as f:
        assert res.content == f.read()
    assert res.headers["Content-Disposition"] == 'attachment; filename="test_responses.py"'

def test_file_response_bytes():
    try:
        res = requests.get(f"http://localhost:{server.port}/file/bytes")
    except:
        assert False, "Could not connect to server"
    assert res.status_code == 200
    assert res.headers["Content-Type"] == "text/x-python"
    with open("tests/test_responses.py", "rb") as f:
        assert res.content == f.read()
    assert res.headers["Content-Disposition"] == 'inline; filename="test_responses.py"'

def test_html_response():
    try:
        res = requests.get(f"http://localhost:{server.port}/html")
    except:
        assert False, "Could not connect to server"
    
    assert res.status_code == 200
    assert res.headers["Content-Type"] == "text/html"

def test_redir_response():
    try:
        res = requests.get(f"http://localhost:{server.port}/redir", allow_redirects=False)
    except:
        assert False, "Could not connect to server"
    
    assert res.status_code == 308
    assert res.headers["Location"] == "/"

