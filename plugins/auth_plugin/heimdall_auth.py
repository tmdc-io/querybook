from flask import request, session as flask_session, redirect
import flask_login

from app.db import with_session, DBSession
from logic.user import get_user_by_name, create_user, update_user, update_user_properties
from app.auth.utils import (
    AuthUser,
    abort_unauthorized,
    AuthenticationError,
    authorize_and_get_user_profile,
    get_or_create_heimdall_user_apikey,
    update_admin_user_role_by_dataos_tags
)
from app.auth.oauth_auth import OAuthLoginManager
from env import QuerybookSettings, get_env_config, get_env_config_strip_slash
from lib.logger import get_logger
from lib.utils.decorators import in_mem_memoized

LOG = get_logger(__file__)

OIDC_CALLBACK_PATH = f"{QuerybookSettings.BASE_PATH}/auth/oidc/callback"

"""
AUTH_BACKEND: 'auth_plugin.heimdall_auth'
OIDC_CLIENT_ID: '...'
OIDC_CLIENT_SECRET: '...'
DATAOS_BASE_URL: https://easily-champion-frog.dataos.io
PUBLIC_URL: http://127.0.0.1:3000
"""


class HeimdallLoginManager(OAuthLoginManager):
    def init_app(self, flask_app):
        super().init_app(flask_app)

        self.flask_app.add_url_rule(
            OIDC_CALLBACK_PATH, "oidc_callback", self.oidc_callback
        )

    def oidc_callback(self):
        if request.args.get("error"):
            return f"<h1>Error: {request.args.get('error')}</h1>"

        code = request.args.get("code")

        try:
            access_token = self._fetch_access_token(code)
            username, email, fullname, tags, profile_img = authorize_and_get_user_profile(access_token)
            user_apikey = get_or_create_heimdall_user_apikey(username, access_token)
            with DBSession() as session:
                flask_login.login_user(
                    AuthUser(self.login_user(username, email, user_apikey, tags, profile_img=profile_img, session=session, fullname=fullname))
                )
        except AuthenticationError:
            abort_unauthorized()

        home_url = (QuerybookSettings.PUBLIC_URL or QuerybookSettings.DATAOS_BASE_URL).rstrip("/")
        next_url = f"{home_url}/{QuerybookSettings.BASE_NAME}"
        if "next" in flask_session:
            next_url = flask_session["next"]
            del flask_session["next"]

        return redirect(next_url)

    @with_session
    def login_user(self, username, email, user_apikey, tags, profile_img=None, session=None, fullname=None):
        """ creates a user (if necessary) and logs him in """
        user = get_user_by_name(username, session=session)
        if not user:
            user = create_user(
                username=username,
                fullname=fullname if fullname is not None else username,
                email=email,
                profile_img=profile_img,
                session=session,
                properties={'heimdall': user_apikey, 'tags': tags},
            )
        else:
            update_user_properties(
                user.id,
                heimdall=user_apikey,
                tags=tags,
                session=session,
            )
            update_user(
                user.id,
                fullname=fullname if fullname is not None else username,
                profile_img=profile_img,
                email=email,
                session=session,
            )

        update_admin_user_role_by_dataos_tags(user.id, username, tags or [], session)
        return user

    @property
    @in_mem_memoized()
    def oauth_config(self):
        client_id = QuerybookSettings.DATAOS_OIDC_CLIENT_ID
        client_secret = QuerybookSettings.DATAOS_OIDC_CLIENT_SECRET
        dataos_base_url = QuerybookSettings.DATAOS_BASE_URL

        callback_url = "{}{}".format(QuerybookSettings.PUBLIC_URL, OIDC_CALLBACK_PATH)
        authorization_url = f"{dataos_base_url}/oidc/auth"
        token_url = f"{dataos_base_url}/oidc/token"
        profile_url = f"{dataos_base_url}/oidc/userinfo"
        scope = ["openid", "profile", "email", "groups", "federated:id"]

        return {
            "callback_url": callback_url,
            "client_id": client_id,
            "client_secret": client_secret,
            "authorization_url": authorization_url,
            "token_url": token_url,
            "profile_url": profile_url,
            "scope": scope,
        }


login_manager = HeimdallLoginManager()

ignore_paths = [OIDC_CALLBACK_PATH]


def init_app(app):
    login_manager.init_app(app)


def login(request):
    return login_manager.login(request)


def oauth_authorization_url():
    return login_manager._get_authn_url()
