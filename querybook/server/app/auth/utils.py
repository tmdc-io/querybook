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
    create_user_role,
    delete_user_role,
    get_all_admin_user_roles_by_user_id,
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
        username = authorize_and_get_username(token_string)
        with DBSession() as session:
            user = get_user_by_name(username, session=session)
            username, email, fullname, tags = get_heimdall_user_profile(
                token_string, username
            )
            if not user:
                user_apikey = get_or_create_heimdall_user_apikey(username, token_string)
                user = create_user(
                    username=username,
                    fullname=fullname if fullname is not None else username,
                    email=email,
                    session=session,
                    properties={"heimdall": user_apikey, "tags": tags},
                )

            update_admin_user_role_by_dataos_tags(
                user.id, username, tags or [], session
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


def update_admin_user_role_by_dataos_tags(uid, username, tags=[], session=None):
    admin_tags = ["dataos:u:querybook", "dataos:u:operator"]

    can_be_admin = tags and any(tag in admin_tags for tag in tags)
    existing_admin_user_roles = get_all_admin_user_roles_by_user_id(uid)
    is_already_admin = len(existing_admin_user_roles) > 0
    LOG.info(
        f"user:{uid}:{username} can_be_admin:{can_be_admin} => is_already_admin:{is_already_admin}"
    )

    if can_be_admin and not is_already_admin:
        LOG.info(f"*** Assigning ADMIN role to {username}")
        create_user_role(uid=uid, role=UserRoleType.ADMIN, session=session)
    elif is_already_admin and not can_be_admin:
        LOG.info(f"*** Removing ADMIN role from {username}")
        for r in existing_admin_user_roles:
            delete_user_role(r.id, session)


def authorize_and_get_username(access_token):
    # Authorize
    heimdall_auth_url = f"{QuerybookSettings.DATAOS_BASE_URL}/heimdall/api/v1/authorize"
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


def authorize_and_get_user_profile(access_token):
    # Authorize
    heimdall_auth_url = f"{QuerybookSettings.DATAOS_BASE_URL}/heimdall/api/v1/authorize"
    LOG.debug(f"[Heimdall] auth_url: {heimdall_auth_url}")

    resp = requests.post(heimdall_auth_url, json={"token": access_token})
    LOG.debug(f"[Heimdall] resp: {resp.status_code}")
    if resp and resp.status_code == 200:
        reply = resp.json()
        LOG.debug(f"[Heimdall] reply: {reply}")
        if reply["allow"] and reply["result"] is not None:
            user_id = reply["result"]["id"]
            return get_heimdall_user_profile(access_token, user_id)
    else:
        raise AuthenticationError(
            "Failed to authorize with Heimdall, status ({0}), body ({1})".format(
                resp.status if resp else "None", resp.json() if resp else "None"
            )
        )


def get_heimdall_user_profile(access_token, username):
    heimdall_profile_url = (
        f"{QuerybookSettings.DATAOS_BASE_URL}/heimdall/api/v1/users/{username}"
    )
    LOG.debug(f"[Heimdall] profile_url: {heimdall_profile_url}")

    headers = {"Authorization": "Bearer {}".format(access_token)}
    resp = requests.get(heimdall_profile_url, headers=headers)
    LOG.debug(f"[Heimdall] resp: {resp.status_code}")
    if resp.status_code == 200:
        user = resp.json()
        LOG.info(f"[Heimdall] resolved user: {user}")
        # username, email, fullname, tags
        return user["id"], user["email"], user["name"], user["tags"]
    else:
        raise AuthenticationError(
            "Failed to fetch user profile, status ({0}), body ({1})".format(
                resp.status if resp else "None",
                resp.json() if resp else "None",
            )
        )


def get_heimdall_users(access_token):
    heimdall_users_url = f"{QuerybookSettings.DATAOS_BASE_URL}/heimdall/api/v1/users"
    LOG.debug(f"[Heimdall] heimdall_users: {heimdall_users_url}")

    headers = {"Authorization": "Bearer {}".format(access_token)}
    resp = requests.get(heimdall_users_url, headers=headers)
    LOG.debug(f"[Heimdall] resp: {resp.status_code}")
    if resp.status_code == 200:
        users = []
        for user in resp.json():
            users.append(
                {
                    "username": user["id"],
                    "fullname": user["name"],
                    "tags": user["tags"],
                    "type": user["type"],
                    "email": user["email"],
                }
            )
        return users
    else:
        raise AuthenticationError(
            "Failed to fetch users, status ({0}), body ({1})".format(
                resp.status if resp else "None",
                resp.json() if resp else "None",
            )
        )


def get_or_create_heimdall_user_apikey(user_id, access_token):
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
        "duration": "8760h",  # 1 Year
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
