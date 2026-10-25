# This quickstart uses Flask, but the Auth0 Python SDK works with any
# framework. For FastAPI, see: https://github.com/auth0/auth0-fastapi
import json
from os import environ as env
from urllib.parse import urlparse
import requests

from auth0_server_python.auth_server.server_client import ServerClient
from auth0_server_python.auth_types import LogoutOptions, StartInteractiveLoginOptions, StateData, TransactionData
from auth0_server_python.store.abstract import AbstractDataStore
from dotenv import load_dotenv
from flask import Flask, after_this_request, redirect, request
from markupsafe import escape

load_dotenv()

app = Flask(__name__)


# highlight-start stores
# The SDK requires two stores: one for session data (user profile, tokens)
# and one for short-lived OAuth flow data (PKCE verifiers, state params).
# Both extend AbstractDataStore which provides encrypt() and decrypt().
# This implementation stores data in encrypted cookies, but you could
# also use Redis, PostgreSQL, or any other backend by implementing
# the same set/get/delete interface.
class CookieStore(AbstractDataStore):
    def __init__(self, secret, cookie_name, max_age, model):
        super().__init__({"secret": secret})
        self.cookie_name = cookie_name
        self.max_age = max_age
        self.model = model

    async def set(self, identifier, state, **_):
        @after_this_request
        def apply(response):
            data = state.model_dump() if hasattr(state, "model_dump") else state
            response.set_cookie(
                self.cookie_name,
                self.encrypt(identifier, data),
                httponly=True,
                samesite="Lax",
                secure=not env.get("APP_BASE_URL", "").startswith("http://"),
                max_age=self.max_age,
            )
            return response

    async def get(self, identifier, options=None):
        try:
            encrypted = options["request"].cookies.get(self.cookie_name)
            return self.model.model_validate(self.decrypt(identifier, encrypted)) if encrypted else None
        except Exception:
            app.logger.warning("Failed to decrypt cookie %s", self.cookie_name, exc_info=True)
            return None

    async def delete(self, *_, **__):
        @after_this_request
        def apply(response):
            response.delete_cookie(self.cookie_name)
            return response
# highlight-end stores


# highlight-start auth-client
def auth0():
    session_secret = env.get("AUTH0_SECRET")

    return ServerClient(
        domain=env.get("AUTH0_DOMAIN"),
        client_id=env.get("AUTH0_CLIENT_ID"),
        client_secret=env.get("AUTH0_CLIENT_SECRET"),
        redirect_uri=env.get("APP_BASE_URL") + "/callback",
        authorization_params={"scope": "openid profile email"},
        secret=session_secret,
        state_store=CookieStore(session_secret, "_a0_session", 259200, StateData),  # 3 days
        transaction_store=CookieStore(session_secret, "_a0_tx", 300, TransactionData),  # 5 min
    )
# highlight-end auth-client


@app.route("/")
async def home():
    # highlight-start session
    user = await auth0().get_user({"request": request})
    # highlight-end session

    head = "<!DOCTYPE html><title>Auth0 Python Sample</title>"

    if user:
        return f"""
            {head}
            <p>Logged in as {escape(user.get("email", ""))}</p>
            <h1>User Profile</h1>
            <pre>{escape(json.dumps(user, indent=2))}</pre>
            <a href="/logout">Logout</a>
        """

    return f"""
        {head}
        <a href="/login?screen_hint=signup">Signup</a>
        <a href="/login">Login</a>
    """


@app.route("/login")
async def login():
    # highlight-start login
    url = await auth0().start_interactive_login(
        options=StartInteractiveLoginOptions(
            authorization_params=dict(request.args),
        ),
        store_options={"request": request},
    )
    # highlight-end login
    return redirect(url)


@app.route("/callback")
async def callback():
    try:
        # highlight-start callback
        await auth0().complete_interactive_login(
            url=request.url, store_options={"request": request},
        )
        # highlight-end callback
        return redirect("/")
    except Exception:
        app.logger.exception("Callback error")
        return "Something went wrong. Check server logs for details.", 400


@app.route("/logout")
async def logout():
    # highlight-start logout
    url = await auth0().logout(
        options=LogoutOptions(return_to=env.get("APP_BASE_URL")),
        store_options={"request": request},
    )
    # highlight-end logout
    return redirect(url)

@app.route("/perfil", methods=["GET", "POST"])
async def perfil():
    user = await auth0().get_user({"request": request})
    if not user:
        return redirect("/login")

    MANAGEMENT_API_TOKEN = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IlFtSDFGbzNCZTJYZTJIdFVYNHBBMiJ9.eyJpc3MiOiJodHRwczovL2Rldi0zMWZqdWZ2YWpka2hueDRkLnVzLmF1dGgwLmNvbS8iLCJzdWIiOiJoVzZtVDd3bGxyUWFrMEVRZ0FpS0hjVGhaV1AzV2NRREBjbGllbnRzIiwiYXVkIjoiaHR0cHM6Ly9kZXYtMzFmanVmdmFqZGtobng0ZC51cy5hdXRoMC5jb20vYXBpL3YyLyIsImlhdCI6MTc5Mjg3NjU0NywiZXhwIjoxNzkyOTYyOTQ3LCJzY29wZSI6InJlYWQ6Y2xpZW50X2dyYW50cyBjcmVhdGU6Y2xpZW50X2dyYW50cyBkZWxldGU6Y2xpZW50X2dyYW50cyB1cGRhdGU6Y2xpZW50X2dyYW50cyByZWFkOnVzZXJzIHVwZGF0ZTp1c2VycyBkZWxldGU6dXNlcnMgY3JlYXRlOnVzZXJzIHJlYWQ6dXNlcnNfYXBwX21ldGFkYXRhIHVwZGF0ZTp1c2Vyc19hcHBfbWV0YWRhdGEgZGVsZXRlOnVzZXJzX2FwcF9tZXRhZGF0YSBjcmVhdGU6dXNlcnNfYXBwX21ldGFkYXRhIHJlYWQ6dXNlcl9jdXN0b21fYmxvY2tzIGNyZWF0ZTp1c2VyX2N1c3RvbV9ibG9ja3MgZGVsZXRlOnVzZXJfY3VzdG9tX2Jsb2NrcyBjcmVhdGU6dXNlcl90aWNrZXRzIHJlYWQ6Y2xpZW50cyB1cGRhdGU6Y2xpZW50cyBkZWxldGU6Y2xpZW50cyBjcmVhdGU6Y2xpZW50cyByZWFkOmNsaWVudF9rZXlzIHVwZGF0ZTpjbGllbnRfa2V5cyBkZWxldGU6Y2xpZW50X2tleXMgY3JlYXRlOmNsaWVudF9rZXlzIHJlYWQ6Y2xpZW50X2NyZWRlbnRpYWxzIHVwZGF0ZTpjbGllbnRfY3JlZGVudGlhbHMgZGVsZXRlOmNsaWVudF9jcmVkZW50aWFscyBjcmVhdGU6Y2xpZW50X2NyZWRlbnRpYWxzIHJlYWQ6Y29ubmVjdGlvbnMgdXBkYXRlOmNvbm5lY3Rpb25zIGRlbGV0ZTpjb25uZWN0aW9ucyBjcmVhdGU6Y29ubmVjdGlvbnMgcmVhZDpyZXNvdXJjZV9zZXJ2ZXJzIHVwZGF0ZTpyZXNvdXJjZV9zZXJ2ZXJzIGRlbGV0ZTpyZXNvdXJjZV9zZXJ2ZXJzIGNyZWF0ZTpyZXNvdXJjZV9zZXJ2ZXJzIHJlYWQ6ZGV2aWNlX2NyZWRlbnRpYWxzIHVwZGF0ZTpkZXZpY2VfY3JlZGVudGlhbHMgZGVsZXRlOmRldmljZV9jcmVkZW50aWFscyBjcmVhdGU6ZGV2aWNlX2NyZWRlbnRpYWxzIHJlYWQ6cnVsZXMgdXBkYXRlOnJ1bGVzIGRlbGV0ZTpydWxlcyBjcmVhdGU6cnVsZXMgcmVhZDpydWxlc19jb25maWdzIHVwZGF0ZTpydWxlc19jb25maWdzIGRlbGV0ZTpydWxlc19jb25maWdzIHJlYWQ6aG9va3MgdXBkYXRlOmhvb2tzIGRlbGV0ZTpob29rcyBjcmVhdGU6aG9va3MgcmVhZDphY3Rpb25zIHVwZGF0ZTphY3Rpb25zIGRlbGV0ZTphY3Rpb25zIGNyZWF0ZTphY3Rpb25zIHJlYWQ6ZW1haWxfcHJvdmlkZXIgdXBkYXRlOmVtYWlsX3Byb3ZpZGVyIGRlbGV0ZTplbWFpbF9wcm92aWRlciBjcmVhdGU6ZW1haWxfcHJvdmlkZXIgYmxhY2tsaXN0OnRva2VucyByZWFkOnN0YXRzIHJlYWQ6aW5zaWdodHMgcmVhZDp0ZW5hbnRfc2V0dGluZ3MgdXBkYXRlOnRlbmFudF9zZXR0aW5ncyByZWFkOmxvZ3MgcmVhZDpsb2dzX3VzZXJzIHJlYWQ6c2hpZWxkcyBjcmVhdGU6c2hpZWxkcyB1cGRhdGU6c2hpZWxkcyBkZWxldGU6c2hpZWxkcyByZWFkOmFub21hbHlfYmxvY2tzIGRlbGV0ZTphbm9tYWx5X2Jsb2NrcyB1cGRhdGU6dHJpZ2dlcnMgcmVhZDp0cmlnZ2VycyByZWFkOmdyYW50cyBkZWxldGU6Z3JhbnRzIHJlYWQ6Z3VhcmRpYW5fZmFjdG9ycyB1cGRhdGU6Z3VhcmRpYW5fZmFjdG9ycyByZWFkOmd1YXJkaWFuX2Vucm9sbG1lbnRzIGRlbGV0ZTpndWFyZGlhbl9lbnJvbGxtZW50cyBjcmVhdGU6Z3VhcmRpYW5fZW5yb2xsbWVudF90aWNrZXRzIHJlYWQ6dXNlcl9pZHBfdG9rZW5zIGNyZWF0ZTpwYXNzd29yZHNfY2hlY2tpbmdfam9iIGRlbGV0ZTpwYXNzd29yZHNfY2hlY2tpbmdfam9iIHJlYWQ6Y3VzdG9tX2RvbWFpbnMgZGVsZXRlOmN1c3RvbV9kb21haW5zIGNyZWF0ZTpjdXN0b21fZG9tYWlucyB1cGRhdGU6Y3VzdG9tX2RvbWFpbnMgcmVhZDplbWFpbF90ZW1wbGF0ZXMgY3JlYXRlOmVtYWlsX3RlbXBsYXRlcyB1cGRhdGU6ZW1haWxfdGVtcGxhdGVzIHJlYWQ6bWZhX3BvbGljaWVzIHVwZGF0ZTptZmFfcG9saWNpZXMgcmVhZDpyb2xlcyBjcmVhdGU6cm9sZXMgZGVsZXRlOnJvbGVzIHVwZGF0ZTpyb2xlcyByZWFkOnByb21wdHMgdXBkYXRlOnByb21wdHMgcmVhZDpicmFuZGluZyB1cGRhdGU6YnJhbmRpbmcgZGVsZXRlOmJyYW5kaW5nIHJlYWQ6bG9nX3N0cmVhbXMgY3JlYXRlOmxvZ19zdHJlYW1zIGRlbGV0ZTpsb2dfc3RyZWFtcyB1cGRhdGU6bG9nX3N0cmVhbXMgY3JlYXRlOnNpZ25pbmdfa2V5cyByZWFkOnNpZ25pbmdfa2V5cyB1cGRhdGU6c2lnbmluZ19rZXlzIHJlYWQ6bGltaXRzIHVwZGF0ZTpsaW1pdHMgY3JlYXRlOnJvbGVfbWVtYmVycyByZWFkOnJvbGVfbWVtYmVycyBkZWxldGU6cm9sZV9tZW1iZXJzIHJlYWQ6ZW50aXRsZW1lbnRzIHJlYWQ6YXR0YWNrX3Byb3RlY3Rpb24gdXBkYXRlOmF0dGFja19wcm90ZWN0aW9uIHJlYWQ6b3JnYW5pemF0aW9uc19zdW1tYXJ5IGNyZWF0ZTphdXRoZW50aWNhdGlvbl9tZXRob2RzIHJlYWQ6YXV0aGVudGljYXRpb25fbWV0aG9kcyB1cGRhdGU6YXV0aGVudGljYXRpb25fbWV0aG9kcyBkZWxldGU6YXV0aGVudGljYXRpb25fbWV0aG9kcyByZWFkOm9yZ2FuaXphdGlvbnMgdXBkYXRlOm9yZ2FuaXphdGlvbnMgY3JlYXRlOm9yZ2FuaXphdGlvbnMgZGVsZXRlOm9yZ2FuaXphdGlvbnMgcmVhZDpvcmdhbml6YXRpb25fZGlzY292ZXJ5X2RvbWFpbnMgdXBkYXRlOm9yZ2FuaXphdGlvbl9kaXNjb3ZlcnlfZG9tYWlucyBjcmVhdGU6b3JnYW5pemF0aW9uX2Rpc2NvdmVyeV9kb21haW5zIGRlbGV0ZTpvcmdhbml6YXRpb25fZGlzY292ZXJ5X2RvbWFpbnMgY3JlYXRlOm9yZ2FuaXphdGlvbl9tZW1iZXJzIHJlYWQ6b3JnYW5pemF0aW9uX21lbWJlcnMgZGVsZXRlOm9yZ2FuaXphdGlvbl9tZW1iZXJzIGNyZWF0ZTpvcmdhbml6YXRpb25fY29ubmVjdGlvbnMgcmVhZDpvcmdhbml6YXRpb25fY29ubmVjdGlvbnMgdXBkYXRlOm9yZ2FuaXphdGlvbl9jb25uZWN0aW9ucyBkZWxldGU6b3JnYW5pemF0aW9uX2Nvbm5lY3Rpb25zIGNyZWF0ZTpvcmdhbml6YXRpb25fbWVtYmVyX3JvbGVzIHJlYWQ6b3JnYW5pemF0aW9uX21lbWJlcl9yb2xlcyBkZWxldGU6b3JnYW5pemF0aW9uX21lbWJlcl9yb2xlcyBjcmVhdGU6b3JnYW5pemF0aW9uX2ludml0YXRpb25zIHJlYWQ6b3JnYW5pemF0aW9uX2ludml0YXRpb25zIGRlbGV0ZTpvcmdhbml6YXRpb25faW52aXRhdGlvbnMgcmVhZDpzY2ltX2NvbmZpZyBjcmVhdGU6c2NpbV9jb25maWcgdXBkYXRlOnNjaW1fY29uZmlnIGRlbGV0ZTpzY2ltX2NvbmZpZyBjcmVhdGU6c2NpbV90b2tlbiByZWFkOnNjaW1fdG9rZW4gZGVsZXRlOnNjaW1fdG9rZW4gcmVhZDpkaXJlY3RvcnlfcHJvdmlzaW9uaW5ncyBjcmVhdGU6ZGlyZWN0b3J5X3Byb3Zpc2lvbmluZ3MgdXBkYXRlOmRpcmVjdG9yeV9wcm92aXNpb25pbmdzIGRlbGV0ZTpkaXJlY3RvcnlfcHJvdmlzaW9uaW5ncyBkZWxldGU6cGhvbmVfcHJvdmlkZXJzIGNyZWF0ZTpwaG9uZV9wcm92aWRlcnMgcmVhZDpwaG9uZV9wcm92aWRlcnMgdXBkYXRlOnBob25lX3Byb3ZpZGVycyBkZWxldGU6cGhvbmVfdGVtcGxhdGVzIGNyZWF0ZTpwaG9uZV90ZW1wbGF0ZXMgcmVhZDpwaG9uZV90ZW1wbGF0ZXMgdXBkYXRlOnBob25lX3RlbXBsYXRlcyBjcmVhdGU6ZW5jcnlwdGlvbl9rZXlzIHJlYWQ6ZW5jcnlwdGlvbl9rZXlzIHVwZGF0ZTplbmNyeXB0aW9uX2tleXMgZGVsZXRlOmVuY3J5cHRpb25fa2V5cyByZWFkOnNlc3Npb25zIHVwZGF0ZTpzZXNzaW9ucyBkZWxldGU6c2Vzc2lvbnMgcmVhZDpyZWZyZXNoX3Rva2VucyB1cGRhdGU6cmVmcmVzaF90b2tlbnMgZGVsZXRlOnJlZnJlc2hfdG9rZW5zIGNyZWF0ZTpzZWxmX3NlcnZpY2VfcHJvZmlsZXMgcmVhZDpzZWxmX3NlcnZpY2VfcHJvZmlsZXMgdXBkYXRlOnNlbGZfc2VydmljZV9wcm9maWxlcyBkZWxldGU6c2VsZl9zZXJ2aWNlX3Byb2ZpbGVzIGNyZWF0ZTpzc29fYWNjZXNzX3RpY2tldHMgZGVsZXRlOnNzb19hY2Nlc3NfdGlja2V0cyByZWFkOmZvcm1zIHVwZGF0ZTpmb3JtcyBkZWxldGU6Zm9ybXMgY3JlYXRlOmZvcm1zIHJlYWQ6Zmxvd3MgdXBkYXRlOmZsb3dzIGRlbGV0ZTpmbG93cyBjcmVhdGU6Zmxvd3MgcmVhZDpmbG93c192YXVsdCByZWFkOmZsb3dzX3ZhdWx0X2Nvbm5lY3Rpb25zIHVwZGF0ZTpmbG93c192YXVsdF9jb25uZWN0aW9ucyBkZWxldGU6Zmxvd3NfdmF1bHRfY29ubmVjdGlvbnMgY3JlYXRlOmZsb3dzX3ZhdWx0X2Nvbm5lY3Rpb25zIHJlYWQ6Zmxvd3NfZXhlY3V0aW9ucyBkZWxldGU6Zmxvd3NfZXhlY3V0aW9ucyByZWFkOmNvbm5lY3Rpb25zX29wdGlvbnMgdXBkYXRlOmNvbm5lY3Rpb25zX29wdGlvbnMgcmVhZDpzZWxmX3NlcnZpY2VfcHJvZmlsZV9jdXN0b21fdGV4dHMgdXBkYXRlOnNlbGZfc2VydmljZV9wcm9maWxlX2N1c3RvbV90ZXh0cyBjcmVhdGU6bmV0d29ya19hY2xzIHVwZGF0ZTpuZXR3b3JrX2FjbHMgcmVhZDpuZXR3b3JrX2FjbHMgZGVsZXRlOm5ldHdvcmtfYWNscyBkZWxldGU6dmRjc190ZW1wbGF0ZXMgcmVhZDp2ZGNzX3RlbXBsYXRlcyBjcmVhdGU6dmRjc190ZW1wbGF0ZXMgdXBkYXRlOnZkY3NfdGVtcGxhdGVzIGNyZWF0ZTpjdXN0b21fc2lnbmluZ19rZXlzIHJlYWQ6Y3VzdG9tX3NpZ25pbmdfa2V5cyB1cGRhdGU6Y3VzdG9tX3NpZ25pbmdfa2V5cyBkZWxldGU6Y3VzdG9tX3NpZ25pbmdfa2V5cyByZWFkOmZlZGVyYXRlZF9jb25uZWN0aW9uc190b2tlbnMgZGVsZXRlOmZlZGVyYXRlZF9jb25uZWN0aW9uc190b2tlbnMgY3JlYXRlOnVzZXJfYXR0cmlidXRlX3Byb2ZpbGVzIHJlYWQ6dXNlcl9hdHRyaWJ1dGVfcHJvZmlsZXMgdXBkYXRlOnVzZXJfYXR0cmlidXRlX3Byb2ZpbGVzIGRlbGV0ZTp1c2VyX2F0dHJpYnV0ZV9wcm9maWxlcyByZWFkOmV2ZW50X3N0cmVhbXMgY3JlYXRlOmV2ZW50X3N0cmVhbXMgZGVsZXRlOmV2ZW50X3N0cmVhbXMgdXBkYXRlOmV2ZW50X3N0cmVhbXMgcmVhZDpldmVudF9kZWxpdmVyaWVzIHVwZGF0ZTpldmVudF9kZWxpdmVyaWVzIGNyZWF0ZTpjb25uZWN0aW9uX3Byb2ZpbGVzIHJlYWQ6Y29ubmVjdGlvbl9wcm9maWxlcyB1cGRhdGU6Y29ubmVjdGlvbl9wcm9maWxlcyBkZWxldGU6Y29ubmVjdGlvbl9wcm9maWxlcyBjcmVhdGU6Z3JvdXBzIHJlYWQ6Z3JvdXBzIHVwZGF0ZTpncm91cHMgZGVsZXRlOmdyb3VwcyByZWFkOmdyb3VwX21lbWJlcnMgY3JlYXRlOmdyb3VwX3JvbGVzIGRlbGV0ZTpncm91cF9yb2xlcyByZWFkOnVzZXJfZWZmZWN0aXZlX3Blcm1pc3Npb25zIHJlYWQ6dXNlcl9lZmZlY3RpdmVfcm9sZXMgcmVhZDpvcmdhbml6YXRpb25fbWVtYmVyX2VmZmVjdGl2ZV9yb2xlcyByZWFkOnVzZXJfcm9sZV9zb3VyY2VfZ3JvdXBzIHJlYWQ6b3JnYW5pemF0aW9uX21lbWJlcl9yb2xlX3NvdXJjZV9ncm91cHMgcmVhZDp1c2VyX3Blcm1pc3Npb25fc291cmNlX3JvbGVzIHJlYWQ6Z3JvdXBfcm9sZXMgcmVhZDpvcmdhbml6YXRpb25fZ3JvdXBzIGNyZWF0ZTpvcmdhbml6YXRpb25fZ3JvdXBzIGRlbGV0ZTpvcmdhbml6YXRpb25fZ3JvdXBzIHJlYWQ6b3JnYW5pemF0aW9uX2dyb3VwX3JvbGVzIGNyZWF0ZTpvcmdhbml6YXRpb25fZ3JvdXBfcm9sZXMgZGVsZXRlOm9yZ2FuaXphdGlvbl9ncm91cF9yb2xlcyBjcmVhdGU6dG9rZW5fZXhjaGFuZ2VfcHJvZmlsZXMgcmVhZDp0b2tlbl9leGNoYW5nZV9wcm9maWxlcyB1cGRhdGU6dG9rZW5fZXhjaGFuZ2VfcHJvZmlsZXMgZGVsZXRlOnRva2VuX2V4Y2hhbmdlX3Byb2ZpbGVzIHJlYWQ6b3JnYW5pemF0aW9uX2NsaWVudF9ncmFudHMgY3JlYXRlOm9yZ2FuaXphdGlvbl9jbGllbnRfZ3JhbnRzIGRlbGV0ZTpvcmdhbml6YXRpb25fY2xpZW50X2dyYW50cyByZWFkOm9yZ2FuaXphdGlvbl9jbGllbnRzIGNyZWF0ZTpvcmdhbml6YXRpb25fY2xpZW50cyB1cGRhdGU6b3JnYW5pemF0aW9uX2NsaWVudHMgZGVsZXRlOm9yZ2FuaXphdGlvbl9jbGllbnRzIHJlYWQ6ZXZlbnRzIGNyZWF0ZTpyYXRlX2xpbWl0X3BvbGljaWVzIHJlYWQ6cmF0ZV9saW1pdF9wb2xpY2llcyB1cGRhdGU6cmF0ZV9saW1pdF9wb2xpY2llcyBkZWxldGU6cmF0ZV9saW1pdF9wb2xpY2llcyBjcmVhdGU6cG9ydGFscyByZWFkOnBvcnRhbHMgdXBkYXRlOnBvcnRhbHMgZGVsZXRlOnBvcnRhbHMgY3JlYXRlOm5ldHdvcmtfYWNsX2tleXMgdXBkYXRlOm5ldHdvcmtfYWNsX2tleXMgcmVhZDpuZXR3b3JrX2FjbF9rZXlzIGRlbGV0ZTpuZXR3b3JrX2FjbF9rZXlzIHJlYWQ6c2VjdXJpdHlfbWV0cmljcyByZWFkOmNvbm5lY3Rpb25zX2tleXMgdXBkYXRlOmNvbm5lY3Rpb25zX2tleXMgY3JlYXRlOmNvbm5lY3Rpb25zX2tleXMgY3JlYXRlOmV4cGVyaW1lbnRhdGlvbiByZWFkOmV4cGVyaW1lbnRhdGlvbiB1cGRhdGU6ZXhwZXJpbWVudGF0aW9uIGRlbGV0ZTpleHBlcmltZW50YXRpb24gY3JlYXRlOmNsaWVudF9wcm9maWxlcyByZWFkOmNsaWVudF9wcm9maWxlcyB1cGRhdGU6Y2xpZW50X3Byb2ZpbGVzIGRlbGV0ZTpjbGllbnRfcHJvZmlsZXMiLCJndHkiOiJjbGllbnQtY3JlZGVudGlhbHMiLCJhenAiOiJoVzZtVDd3bGxyUWFrMEVRZ0FpS0hjVGhaV1AzV2NRRCJ9.VSszvbIex4mjosgAH6VPMmYjAb7-KWJwxtjTvKFP_45GdrkM32cgnDZtG2rBwOY_K29Rwyi1dt77SMDUh0cI0CHiMUQ5UUmKjq3Qn1Nn4Cp_IRII-gLL0CM-SkbMi7W66LAYbSIK8QH38BvvovbmZSNsHz30lnvGUBtxnImHQ7NXYhfwgOwz3ZBkkKWeIbaWtbQsVa2T_hz0gEX3MXW0KpIVFMXU8-cUYdQP-rejs6byqjY4t0OQBgipdGp7N5vzblYXA4OOmaYs8Dl4h02rQKAVj3f3EntgUs7429rr3zCuiGv1qezV6JtsPUwKe-eVM65CYblOPrKvTfPc_9_CVg"
    DOMAIN = env.get("AUTH0_DOMAIN")
    USER_ID = user.get("sub")
    
    url = f"https://{DOMAIN}/api/v2/users/{USER_ID}"
    headers = {
        "Authorization": f"Bearer {MANAGEMENT_API_TOKEN}",
        "Content-Type": "application/json"
    }

    if request.method == "POST":
        payload = {
            "user_metadata": {
                "tipo_documento": request.form.get("tipo_documento"),
                "numero_documento": request.form.get("numero_documento"),
                "direccion": request.form.get("direccion"),
                "telefono": request.form.get("telefono")
            }
        }
        requests.patch(url, json=payload, headers=headers)
        return redirect("/")

    resp = requests.get(url, headers=headers)
    user_metadata = resp.json().get("user_metadata", {}) if resp.status_code == 200 else {}

    return f"""
    <!DOCTYPE html>
    <html>
        <head><title>Modificar Datos</title></head>
        <body style="font-family: Arial; padding: 20px;">
            <h2>Modificar Datos del Usuario</h2>
            <form method="POST">
                <label>Tipo de Documento:</label><br>
                <input type="text" name="tipo_documento" value="{escape(user_metadata.get('tipo_documento', ''))}" required><br><br>

                <label>Número de Documento:</label><br>
                <input type="text" name="numero_documento" value="{escape(user_metadata.get('numero_documento', ''))}" required><br><br>

                <label>Dirección:</label><br>
                <input type="text" name="direccion" value="{escape(user_metadata.get('direccion', ''))}" required><br><br>

                <label>Teléfono:</label><br>
                <input type="text" name="telefono" value="{escape(user_metadata.get('telefono', ''))}" required><br><br>

                <button type="submit">Actualizar Datos en Auth0</button>
            </form>
            <br>
            <a href="/">Volver al Inicio</a>
        </body>
    </html>
    """

if __name__ == "__main__":
    url = urlparse(env.get("APP_BASE_URL"))
    app.run(host=url.hostname, port=url.port or 5000)
