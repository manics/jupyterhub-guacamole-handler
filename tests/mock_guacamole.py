#!/usr/bin/env python
from base64 import standard_b64decode
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import json
import os
import sys
from tornado import ioloop, web
from urllib.parse import parse_qs


def decrypt(formdata, key):
    null_iv = 32 * "0"
    cipher = Cipher(
        algorithms.AES128(bytes.fromhex(key)), modes.CBC(bytes.fromhex(null_iv))
    )
    decryptor = cipher.decryptor()
    data = parse_qs(formdata.decode())
    data = data["data"][0]
    plaintext = decryptor.update(standard_b64decode(data)) + decryptor.finalize()
    pad_len = int(plaintext[-1])
    return json.loads(plaintext[32:-pad_len].decode())


class MockGuacamoleHandler(web.RequestHandler):
    def post(self, path):
        d = decrypt(self.request.body, os.getenv("JSON_SECRET_KEY"))
        print(f"{d}")
        r = f"{d['username']}/{''.join(d['connections'].keys())}"
        self.write(json.dumps({"authToken": r}))


def make_app():
    return web.Application(
        [
            (r"/(.*)", MockGuacamoleHandler),
        ]
    )


if __name__ == "__main__":
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    else:
        port = 14822
    app = make_app()
    app.listen(port)
    ioloop.IOLoop.current().start()
