import requests
import hashlib
import flask
from flask_login import UserMixin, LoginManager
from flask import abort, session as flask_session

from app.db import with_session
from const.datasources import ACCESS_RESTRICTED_STATUS_CODE, UNAUTHORIZED_STATUS_CODE
from const.user_roles import UserRoleType

# from lib.utils.decorators import in_mem_memoized
from models.user import User
from app.db import DBSession, get_session
from logic.admin import get_api_access_token
from logic.environment import get_all_accessible_environment_ids_by_uid
from logic.user import (
    get_user_by_name,
    get_user_by_id,
    create_user,
    # update_user_properties,
)
from env import QuerybookSettings
from lib.logger import get_logger

LOG = get_logger(__file__)


class AuthenticationError(Exception):
    pass


class AuthUser(UserMixin):
    def __init__(self, user: User):
        self._user_dict = user.to_dict(with_roles=True)

    @property
    def id(self):
        return self._user_dict["id"]

    def get_id(self):
        return str(self.id)

    @property
    def is_admin(self):
        return UserRoleType.ADMIN.value in self._user_dict["roles"]

    @property
    # @in_mem_memoized(300)
    def environment_ids(self):
        return get_all_accessible_environment_ids_by_uid(self.id, session=get_session())


class QuerybookLoginManager(LoginManager):
    def __init__(self, *args, **kwargs):
        super(QuerybookLoginManager, self).__init__(*args, **kwargs)

        self.request_loader(load_user_with_api_access_token)
        self.user_loader(load_user)
        self.needs_refresh_message = (
            "To protect your account, please reauthenticate to access this page."
        )
        self.needs_refresh_message_category = "info"


@with_session
def load_user(uid, session=None):
    if not uid or uid == "None":
        return None
    user = get_user_by_id(uid, session=session)
    if user is None:
        # Invalid user, clear session
        flask_session.clear()
        flask.abort(401, description="Invalid cookie")

    return AuthUser(user)


def load_user_with_api_access_token(request):
    token_string = request.headers.get("api-access-token")
    if token_string:
        with DBSession() as session:
            token_validation = get_api_access_token(token_string)
            if token_validation:
                if token_validation.enabled:
                    user = get_user_by_id(token_validation.creator_uid, session=session)
                    return AuthUser(user)
                else:
                    flask.abort(401, description="Token is disabled.")
            else:
                flask.abort(401, description="Token is invalid.")

    bearer_token = request.headers.get("Authorization")
    if bearer_token:
        token_string = bearer_token.lstrip("Bearer").strip()
    if not bearer_token:
        token_string = request.headers.get("apikey")

    if token_string:
        user_id = authorize_with_heimdall(token_string)
        with DBSession() as session:
            user = get_user_by_name(user_id, session=session)
            if not user:
                username, email, fullname, tags = get_dataos_user_profile(token_string)
                user_apikey = get_or_create_dataos_user_apikey(username, token_string)
                user = create_user(
                    username=username,
                    fullname=fullname if fullname is not None else username,
                    email=email,
                    session=session,
                    properties={"heimdall": user_apikey, "tags": tags},
                )
            return AuthUser(user)

    return None


def abort_unauthorized():
    """
    Indicate that authorization is required
    :return:
    """
    abort(UNAUTHORIZED_STATUS_CODE)


def abort_forbidden():
    abort(ACCESS_RESTRICTED_STATUS_CODE)


def authorize_with_heimdall(access_token):
    dataos_base_url = QuerybookSettings.DATAOS_BASE_URL
    heimdall_base_url = f"{dataos_base_url}/heimdall"

    # Authorize
    heimdall_auth_url = f"{heimdall_base_url}/api/v1/authorize"
    LOG.debug(f"[Heimdall] auth_url: {heimdall_auth_url}")

    resp = requests.post(heimdall_auth_url, json={"token": access_token})
    LOG.debug(f"[Heimdall] resp: {resp.status_code}")

    if resp and resp.status_code == 200:
        reply = resp.json()
        LOG.debug(f"[Heimdall] reply: {reply}")
        if reply["allow"] and reply["result"] is not None:
            user_id = reply["result"]["id"]
            return user_id

    raise AuthenticationError(
        "Failed to authorize with Heimdall, status ({0}), body ({1})".format(
            resp.status if resp else "None", resp.json() if resp else "None"
        )
    )


def get_dataos_user_profile(access_token):
    dataos_base_url = QuerybookSettings.DATAOS_BASE_URL
    heimdall_base_url = f"{dataos_base_url}/heimdall"

    # Authorize
    heimdall_auth_url = f"{heimdall_base_url}/api/v1/authorize"
    LOG.debug(f"[Heimdall] auth_url: {heimdall_auth_url}")

    resp = requests.post(heimdall_auth_url, json={"token": access_token})
    LOG.debug(f"[Heimdall] resp: {resp.status_code}")
    if resp and resp.status_code == 200:
        reply = resp.json()
        LOG.debug(f"[Heimdall] reply: {reply}")
        if reply["allow"] and reply["result"] is not None:
            user_id = reply["result"]["id"]

            # Profile
            heimdall_profile_url = f"{heimdall_base_url}/api/v1/users/{user_id}"
            LOG.debug(f"[Heimdall] profile_url: {heimdall_profile_url}")

            headers = {"Authorization": "Bearer {}".format(access_token)}
            resp = requests.get(heimdall_profile_url, headers=headers)
            LOG.debug(f"[Heimdall] resp: {resp.status_code}")
            if resp.status_code == 200:
                user = resp.json()
                LOG.info(f"[Heimdall] resolved user: {user}")
                return user["id"], user["email"], user["name"], user["tags"]
            else:
                raise AuthenticationError(
                    "Failed to fetch user profile, status ({0}), body ({1})".format(
                        resp.status if resp else "None",
                        resp.json() if resp else "None",
                    )
                )
    else:
        raise AuthenticationError(
            "Failed to authorize with Heimdall, status ({0}), body ({1})".format(
                resp.status if resp else "None", resp.json() if resp else "None"
            )
        )


def get_or_create_dataos_user_apikey(user_id, access_token):
    dataos_base_url = QuerybookSettings.DATAOS_BASE_URL
    heimdall_base_url = f"{dataos_base_url}/heimdall"
    heimdall_apikey_url = f"{heimdall_base_url}/api/v1/users/{user_id}/tokens"

    user_hash = hashlib.md5(user_id.encode()).hexdigest()
    querybook_token_name = "querybook_{}".format(user_hash)

    headers = {"Authorization": "Bearer {}".format(access_token)}
    json = {
        "use_existing": True,
        "type": "apikey",
        "name": querybook_token_name,
        "duration": "8760h",
    }

    LOG.debug(f"[Heimdall] apikey_url: {heimdall_apikey_url} json: {json}")

    resp = requests.post(
        heimdall_apikey_url,
        headers=headers,
        json=json,
    )

    LOG.debug(f"[Heimdall] resp: {resp.status_code} {resp.json()}")

    if resp.status_code == 200 or resp.status_code == 201:
        token = resp.json()
        return token["data"]["apikey"]
    else:
        raise AuthenticationError(
            "Failed to get_or_create apikey from Heimdall, status ({0}), body ({1})".format(
                resp.status if resp else "None", resp.json() if resp else "None"
            )
        )
