import json
import re
from urllib.parse import urlparse

import pytest
from tornado.httpclient import AsyncHTTPClient


def update_cookiejar(jar, headers):
    for h in headers.get_list("Set-Cookie"):
        d = {}
        parts = re.split(" *; *", h)
        for p in parts:
            if "=" in p:
                k, v = p.split("=", 1)
                d[k] = v
            else:
                d[p] = True
        print(f"Adding cookie {d}")
        jar.update(d)


def cookiejar_join(cookiejar, path):
    path = urlparse(path).path
    selected = {}
    for cookie in cookiejar:
        # Good enough for testing
        if path.startswith(cookie.path):
            selected[cookie.name] = cookie.value
    return "; ".join(f"{k}={v}" for (k, v) in selected.items())


async def fetch(client, url, cookiejar, **kwargs):
    cookies = cookiejar_join(cookiejar, url)
    r = await client.fetch(url, headers={"Cookie": cookies}, **kwargs)
    return r


@pytest.mark.asyncio
@pytest.mark.parametrize("namedserver", ["", "name"])
async def test_guacamole_handler(app, namedserver):
    hub = app["hub"]
    assert hub.config.JupyterHub.services

    base = f"{hub.bind_url}"
    parts = urlparse(base)
    host = f"{parts.scheme}://{parts.netloc}"

    cookiejar = await hub.login_user("test")

    client = AsyncHTTPClient()

    if namedserver:
        spawn_url = f"{base}hub/spawn/test/{namedserver}"
    else:
        spawn_url = f"{base}hub/spawn/test"
    r = await fetch(client, spawn_url, cookiejar)

    r = await fetch(client, f"{base}hub/api/user", cookiejar)
    d = json.loads(r.body.decode())
    assert d["name"] == "test"
    assert d["servers"][namedserver]

    r = await fetch(
        client,
        f"{base}services/guacamole-handler/{namedserver}",
        cookiejar,
        follow_redirects=False,
        raise_error=False,
    )
    assert r.code == 302

    update_cookiejar(cookiejar, r.headers)
    r = await fetch(
        client,
        f"{host}{r.headers.get('Location')}",
        cookiejar,
        follow_redirects=False,
        raise_error=False,
    )
    assert r.code == 302
    assert not r.headers.get("Set-Cookie")

    r = await fetch(
        client,
        f"{host}{r.headers.get('Location')}",
        cookiejar,
        follow_redirects=False,
        raise_error=False,
    )
    assert r.code == 302
    assert r.headers.get("Set-Cookie")

    update_cookiejar(cookiejar, r.headers)
    r = await fetch(
        client,
        f"{host}{r.headers.get('Location')}",
        cookiejar,
        follow_redirects=False,
        raise_error=False,
    )
    assert r.code == 200
    assert not r.headers.get("Set-Cookie")
    body = r.body.decode()

    guacamole_url = f"http://localhost:{app['mock_guacamole_port']}/guacamole/#/client/"
    if namedserver:
        assert f"{guacamole_url}?token=test/jupyter-test-vnc" in body
    else:
        assert f"{guacamole_url}?token=test/jupyter-test-rdp" in body


@pytest.mark.asyncio
async def test_guacamole_health(app):
    client = AsyncHTTPClient()
    # Should not include JUPYTERHUB_SERVICE_PREFIX
    health_url = f"http://localhost:{app['guacamole_handler_port']}/health"
    r = await client.fetch(health_url)
    assert r.code == 200
    d = json.loads(r.body.decode())
    assert d == {"status": "ok"}
