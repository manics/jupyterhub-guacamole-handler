import socket
import sys
from pathlib import Path
import signal
from pytest_asyncio import fixture as asyncio_fixture


pytest_plugins = ["asyncio", "jupyterhub-spawners-plugin"]


HERE = Path(__file__).parent


@asyncio_fixture(scope="function")
async def app(configured_mockhub_instance):
    guacamole_handler_port = random_port()
    mock_guacamole_port = random_port()
    config = {
        "JupyterHub": {
            "allow_named_servers": True,
            "load_roles": [
                {
                    "name": "user",
                    # grant all users access to all services
                    "scopes": ["access:services", "self"],
                },
                {
                    "name": "guacamole-handler",
                    "scopes": [
                        "read:servers",
                        "admin:server_state",
                    ],
                    "services": ["guacamole-handler"],
                },
            ],
            "services": [
                # The service we're testing
                {
                    "name": "guacamole-handler",
                    "url": f"http://127.0.0.1:{guacamole_handler_port}",
                    "command": [
                        sys.executable,
                        str(HERE / ".." / "guacamole_handler" / "guacamole_handler.py"),
                        "--log-level=debug",
                    ],
                    "environment": {
                        "GUACAMOLE_HOST": f"http://localhost:{mock_guacamole_port}",
                        "JSON_SECRET_KEY": "0123456789abcdef0123456789abcdef",
                    },
                    "oauth_no_confirm": True,
                },
                # A mock Apache Guacamole service.
                # Completely independent of JupyterHub, but since we need a way
                # to run it we might as well get JupyterHub to run it for us
                {
                    "name": "mock-guacamole",
                    "command": [
                        sys.executable,
                        str(HERE / "mock_guacamole.py"),
                        str(mock_guacamole_port),
                    ],
                    "environment": {
                        "JSON_SECRET_KEY": "0123456789abcdef0123456789abcdef",
                    },
                },
            ],
        }
    }

    app = (await configured_mockhub_instance)(config=config)
    await app.initialize()
    await app.start()
    yield app, mock_guacamole_port
    # https://github.com/jupyterhub/pytest-jupyterhub/blob/73ba84066d2646e13a1a8b0ca6bbfbd186d6c44d/pytest_jupyterhub/jupyterhub_spawners.py#L78-L86
    # app.stop()
    app.http_server.stop()
    await app.shutdown_cancel_tasks(sig=signal.SIGTERM)


def random_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    s.listen(1)
    port = s.getsockname()[1]
    s.close()
    return port
