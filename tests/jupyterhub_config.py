# Configuration file for jupyterhub-demo
import sys

# from jupyterhub.auth import DummyAuthenticator
from jupyterhub.spawner import SimpleLocalProcessSpawner

c = get_config()  # noqa
# c.Application.log_level = 'DEBUG'

# c.Spawner.disable_user_config = True


class MockGuacSpawner(SimpleLocalProcessSpawner):
    # Override simple spawner to include dns_name and connection in state

    def get_state(self):
        state = super().get_state()
        state["desktop_connection"] = "rdp"
        state["dns_name"] = "server-mock.example.org"
        return state


# Use memory
# c.JupyterHub.db_url = "sqlite://"

c.JupyterHub.authenticator_class = "dummy"
c.JupyterHub.spawner_class = MockGuacSpawner
c.Authenticator.admin_users = {"admin", "demo"}

c.JupyterHub.allow_named_servers = True
c.JupyterHub.named_server_limit_per_user = 2


c.JupyterHub.services = [
    {
        "name": "guacamole-handler",
        "url": "http://127.0.0.1:10102",
        "command": [
            sys.executable,
            "../guacamole_handler/guacamole_handler.py",
            "--log-level=debug",
        ],
        "environment": {
            "GUACAMOLE_HOST": "http://localhost:14822",
            "JSON_SECRET_KEY": "0123456789abcdef0123456789abcdef",
        },
        # "oauth_roles": ["guacamole-handler"],
    },
]


c.JupyterHub.load_roles = [
    {
        "name": "admin",
        "users": ["demo"],
    },
    {
        # For testing Hub API using notebooks
        "name": "server",
        "scopes": ["inherit"],
    },
    {
        "name": "user",
        # grant all users access to all services
        "scopes": ["access:services", "self"],
    },
    {
        "name": "guacamole-handler",
        "scopes": [
            # "read:users",
            "read:servers",
            "admin:server_state",
            # "self",
        ],
        "services": ["guacamole-handler"],
    },
]

# Don't automatically go to server, easier to test hub
c.JupyterHub.default_url = "/hub/home"
