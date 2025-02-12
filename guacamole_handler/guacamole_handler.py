"""
Fetch a token from Guacamole

https://github.com/jupyterhub/jupyterhub/blob/5.0.0/examples/service-whoami/whoami-oauth.py
"""

import json
import os
from urllib.parse import urlparse

from tornado.httpclient import AsyncHTTPClient, HTTPRequest
from tornado.httpserver import HTTPServer
from tornado.ioloop import IOLoop
from tornado.web import Application
from tornado.web import authenticated
from tornado.web import HTTPError
from tornado.web import RequestHandler

from jupyterhub.services.auth import HubOAuthCallbackHandler
from jupyterhub.services.auth import HubOAuthenticated
from jupyterhub.utils import url_path_join

from base64 import standard_b64encode
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import hmac
import hashlib
import logging
from time import time
from tornado.escape import url_escape
from http.client import responses

log = logging.getLogger("jupyterhub_guacamole")

GUACAMOLE_HOST = os.environ["GUACAMOLE_HOST"]
GUACAMOLE_PUBLIC_HOST = os.environ["GUACAMOLE_PUBLIC_HOST"]
JSON_SECRET_KEY = os.environ["JSON_SECRET_KEY"]


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


async def guacamole_url(username, protocol):
    expiry_ms = int(time() * 1000) + 60000
    data = {
        "username": username,
        "expires": expiry_ms,
        "connections": {},
    }

    if protocol == "vnc":
        data["connections"] = {
            f"jupyter-{username}-vnc": {
                "protocol": "vnc",
                "parameters": {"hostname": f"jupyter-{username}", "port": "5901"},
            }
        }
    elif protocol == "rdp":
        data["connections"] = {
            f"jupyter-{username}-rdp": {
                "protocol": "rdp",
                "parameters": {
                    "hostname": f"jupyter-{username}",
                    "port": "3389",
                    "username": "ubuntu",
                    "password": "IGNORED",
                    "ignore-cert": "true",
                },
            }
        }
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


class GuacamoleHandler(HubOAuthenticated, RequestHandler):
    @authenticated
    async def get(self):
        user_model = self.get_current_user()
        log.debug(f"user_model: {user_model}")

        # Note if server field is missing (not just empty) this means the oauth
        # scopes are missing
        if not user_model["server"]:
            # This may be out of date, make an API call to refresh server info
            token = self.hub_auth.get_token(self)
            http_client = AsyncHTTPClient()
            response = await http_client.fetch(
                f"{self.hub_auth.api_url}/user",
                headers={"Authorization": f"token {token}"},
            )
            if response.error:
                raise HTTPError(500, reason="Failed to get user info")

            user = json.loads(response.body)
            if not user["server"]:
                log.error(f"user: {user_model}")
                raise HTTPError(409, reason="User's server is not running")

        urls = {}
        connection = user["server"]["state"].get("connection")
        if not connection or connection == "rdp":
            rdp = await guacamole_url(user_model["name"], "rdp")
            urls["rdp"] = (
                f"{GUACAMOLE_PUBLIC_HOST}/guacamole/#/client/?token={rdp['authToken']}"
            )
        if not connection or connection == "vnc":
            vnc = await guacamole_url(user_model["name"], "vnc")
            urls["vnc"] = (
                f"{GUACAMOLE_PUBLIC_HOST}/guacamole/#/client/?token={vnc['authToken']}"
            )
        log.info(f"Created Guacamole URL(s) for {user_model['name']} default server")
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
    app = Application(
        [
            (os.environ["JUPYTERHUB_SERVICE_PREFIX"], GuacamoleHandler),
            (
                url_path_join(
                    os.environ["JUPYTERHUB_SERVICE_PREFIX"], "oauth_callback"
                ),
                HubOAuthCallbackHandler,
            ),
            ("/health/?", HealthHandler),
            (r".*", GuacamoleHandler),
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
    log.setLevel("INFO")
    h = logging.StreamHandler()
    h.setFormatter(
        logging.Formatter(
            "[%(levelname)1.1s %(asctime)s %(module)s:%(lineno)d] %(message)s"
        )
    )
    log.addHandler(h)
    main()
