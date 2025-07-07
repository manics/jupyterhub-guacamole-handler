#!/usr/bin/env python
"""
Fetch a token from Guacamole

https://github.com/jupyterhub/jupyterhub/blob/5.0.0/examples/service-whoami/whoami-oauth.py
"""

import hashlib
import hmac
import json
import logging
import os
from argparse import ArgumentParser
from base64 import standard_b64encode
from http.client import responses
from time import time
from urllib.parse import urlparse

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from jupyterhub.services.auth import HubOAuthCallbackHandler, HubOAuthenticated
from jupyterhub.utils import url_path_join
from tornado.escape import url_escape
from tornado.httpclient import AsyncHTTPClient, HTTPRequest
from tornado.httpserver import HTTPServer
from tornado.ioloop import IOLoop
from tornado.web import Application, HTTPError, RequestHandler, authenticated

log = logging.getLogger("jupyterhub_guacamole")

GUACAMOLE_HOST = os.environ["GUACAMOLE_HOST"]
GUACAMOLE_PUBLIC_HOST = os.getenv("GUACAMOLE_PUBLIC_HOST", GUACAMOLE_HOST)
# Must be 128 bits (32 hex digits)
JSON_SECRET_KEY = os.environ["JSON_SECRET_KEY"]

JUPYTERHUB_API_TOKEN = os.environ["JUPYTERHUB_API_TOKEN"]
JUPYTERHUB_SERVICE_PREFIX = os.environ["JUPYTERHUB_SERVICE_PREFIX"]


def sign(key, message):
    # openssl dgst -sha256 -mac HMAC -macopt hexkey:"$KEY" -binary <data>
    signature = hmac.new(bytes.fromhex(key), message, hashlib.sha256).digest()
    return signature


def encrypt(key, message):
    # openssl enc -aes-128-cbc -K "$KEY" -iv "$NULL_IV" -nosalt -a <stdin>
    null_iv = 32 * "0"

    # pkcs7 padding
    pad = 16 - (len(message) % 16)
    padding = bytes([pad] * pad)

    cipher = Cipher(
        algorithms.AES128(bytes.fromhex(key)), modes.CBC(bytes.fromhex(null_iv))
    )
    encryptor = cipher.encryptor()
    ct = encryptor.update(message + padding) + encryptor.finalize()
    return ct


async def guacamole_url(
    jupyterhub_username, hostname, protocol, username=None, password=None
):
    """
    Create a temporary Guacamole access URL

    jupyterhub_username: JupyterHub username, used to identify the user/connection
    hostname: Hostname to connect to a users's server
    protocol: Connection protocol, `rdp` or `vnc`
    username: Username to connect to the user's server (different from jupyterhub_username)
    password: Password to connect to the user's server
    """
    expiry_ms = int(time() * 1000) + 60000
    data = {
        "username": jupyterhub_username,
        "expires": expiry_ms,
        "connections": {},
    }

    if protocol == "vnc":
        connection = {
            "protocol": "vnc",
            "parameters": {"hostname": hostname, "port": "5901"},
        }
        if username is not None:
            connection["parameters"]["username"] = username
        if password is not None:
            connection["parameters"]["password"] = password
        data["connections"] = {f"jupyter-{jupyterhub_username}-vnc": connection}

    elif protocol == "rdp":
        connection = {
            "protocol": "rdp",
            "parameters": {
                "hostname": hostname,
                "port": "3389",
                "ignore-cert": "true",
            },
        }
        if username is not None:
            connection["parameters"]["username"] = username
        if password is not None:
            connection["parameters"]["password"] = password
        data["connections"] = {f"jupyter-{jupyterhub_username}-rdp": connection}
    else:
        raise ValueError(f"Invalid protocol: {protocol}")

    message = json.dumps(data).encode()

    signature = sign(JSON_SECRET_KEY, message)
    ciphertext = encrypt(JSON_SECRET_KEY, signature + message)

    http_client = AsyncHTTPClient()
    body = "data=" + url_escape(standard_b64encode(ciphertext))
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "content-length": str(len(body)),
    }
    log.debug(f"Fetching {GUACAMOLE_HOST}/guacamole/api/tokens {message}")
    request = HTTPRequest(
        f"{GUACAMOLE_HOST}/guacamole/api/tokens",
        "POST",
        headers=headers,
        body=body,
    )
    response = await http_client.fetch(request)
    if response.error:
        d = response.error
        log.error(f"ERROR [guacamole]: {d}")
        raise HTTPError(500, "Failed to get Guacamole token")
    else:
        d = json.loads(response.body)
    return d


def _redact_sensitive(data):
    """
    Recursively create a deep copy of a dictionary, redacting values
    for sensitive keys
    """
    if not isinstance(data, dict):
        return data

    redacted_data = {}
    for key, value in data.items():
        if isinstance(value, dict):
            redacted_data[key] = _redact_sensitive(value)
        elif "password" in str(key).lower():
            redacted_data[key] = "********"
        else:
            redacted_data[key] = value
    return redacted_data


class GuacamoleHandler(HubOAuthenticated, RequestHandler):
    def get_template_path(self):
        return os.path.join(os.path.dirname(__file__), "templates")

    @authenticated
    async def get(self, servername=""):
        current_user_model = self.get_current_user()
        log.debug(f"{current_user_model=}")
        if not current_user_model:
            raise HTTPError(403, reason="Missing user")

        # Server state information requires admin scopes, so make the request
        # using the service's own token
        # token = self.hub_auth.get_token(self)
        token = JUPYTERHUB_API_TOKEN
        http_client = AsyncHTTPClient()
        response = await http_client.fetch(
            f"{self.hub_auth.api_url}/users/{current_user_model['name']}",
            headers={"Authorization": f"Bearer {token}"},
        )
        if response.error:
            raise HTTPError(500, reason="Failed to get user info")

        user = json.loads(response.body)
        user_redacted = _redact_sensitive(user)
        log.debug(f"user={user_redacted}")

        server = user["servers"].get(servername)
        if not server:
            log.error(f"user server '{servername}' isn't running: {user_redacted}")
            raise HTTPError(409, reason="User's server is not running")

        urls = {}
        # All these fields in server state must be set by the Spawner
        connection = server["state"].get("desktop_connection")
        dns_name = server["state"].get("dns_name")
        username = server["state"].get("desktop_username")
        password = server["state"].get("desktop_password")

        invalid_state = False
        if not dns_name:
            log.error(
                f"user server '{servername}' state is missing dns_name: {user_redacted}"
            )
            invalid_state = True
        if not connection:
            log.error(
                f"user server '{servername}' state is missing connection: {user_redacted}"
            )
            invalid_state = True
        if connection not in {"rdp", "vnc"}:
            log.error(
                f"user server '{servername}' state has invalid connection: {user_redacted}"
            )
            invalid_state = True
        if invalid_state:
            raise HTTPError(
                500, reason="Failed to get connection details for user server"
            )

        url = await guacamole_url(
            user["name"], dns_name, connection, username, password
        )
        urls[connection] = (
            f"{GUACAMOLE_PUBLIC_HOST}/guacamole/#/client/?token={url['authToken']}"
        )

        log.info(f"Created Guacamole URL(s) for {user['name']} default server")
        # self.set_header("content-type", "application/json")
        # self.write(json.dumps(d, indent=2, sort_keys=True))
        # self.redirect(url)
        self.render("index.html", guacamole_urls=urls)

    def write_error(self, status_code, **kwargs):
        exc_info = kwargs.get("exc_info")
        reason = responses.get(status_code, "Unknown HTTP Error")
        message = ""
        if exc_info:
            exception = exc_info[1]
            r = getattr(exception, "reason", "")
            if r:
                reason = r
            message = getattr(exception, "message", "")

        self.set_status(status_code, reason)
        self.render(
            "error.html", status_code=status_code, reason=reason, message=message
        )


class HealthHandler(RequestHandler):
    async def get(self):
        self.set_header("content-type", "application/json")
        self.write(json.dumps({"status": "ok"}, indent=2, sort_keys=True))


def main():
    def rule(p, *args):
        return (url_path_join(JUPYTERHUB_SERVICE_PREFIX, p), *args)

    app = Application(
        [
            rule("", GuacamoleHandler),
            rule("oauth_callback", HubOAuthCallbackHandler),
            ("/health/?", HealthHandler),
            # TODO: Enforce naming restrictions on user and server names in JupyterHub
            rule(r"(?P<servername>[^/]*)", GuacamoleHandler),
        ],
        cookie_secret=os.urandom(32),
    )

    http_server = HTTPServer(app)

    jh_service_url = os.getenv("JUPYTERHUB_SERVICE_URL")
    if jh_service_url:
        url = urlparse(jh_service_url)
        hostname = url.hostname
        port = url.port
    else:
        hostname = ""
        port = 8040

    log.info(f"Listening on {hostname}:{port}")
    http_server.listen(port, hostname)
    IOLoop.current().start()


if __name__ == "__main__":
    parser = ArgumentParser("JupyterHub Guacamole handler")
    parser.add_argument("--log-level", default="INFO", help="Log level")
    args = parser.parse_args()
    log.setLevel(args.log_level.upper())
    h = logging.StreamHandler()
    h.setFormatter(
        logging.Formatter(
            "[%(levelname)1.1s %(asctime)s %(module)s:%(lineno)d] %(message)s"
        )
    )
    log.addHandler(h)
    main()
