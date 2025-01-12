import sys
import os
import json

from lib.config import get_config_value

in_test = hasattr(sys, "_called_from_test")
querybook_config = get_config_value("querybook_config", {})
querybook_default_config = get_config_value("querybook_default_config", {})


class MissingConfigException(Exception):
    pass


def get_env_config(name, optional=True):
    found = True
    val = None

    if name in os.environ:
        val = os.environ.get(name)
    elif name in querybook_config:
        val = querybook_config.get(name)
    elif name in querybook_default_config:
        val = querybook_default_config.get(name)
        found = val is not None
    else:
        found = False
    # We treat empty string as None as well
    if not found and not optional and not in_test:
        raise MissingConfigException(
            "{} is required to start the process.".format(name)
        )
    return val


def get_env_config_strip_slash(name, optional=True):
    """
    This method fetches a value from Env and strip the trailing /
    """
    val = get_env_config(name, optional)
    if val and type(val) == str:
        val = val.rstrip("/")

    return val


def get_user_agent():
    source = "{0}/{1}".format(
        get_env_config("QUERYBOOK_APPNAME") or "querybook",
        get_env_config("APP_VERSION") or "dev",
    )
    return source


def parse_boolean(s):
    """Takes a string and returns the equivalent as a boolean value."""
    s = s.strip().lower()
    if s in ("yes", "true", "on", "1"):
        return True
    elif s in ("no", "false", "off", "0", "none"):
        return False
    else:
        raise ValueError("Invalid boolean value %r" % s)


class QuerybookSettings(object):
    BASE_NAME = "querybook"
    BASE_PATH = f"/{BASE_NAME}"

    APP_NAME = get_env_config("APP_NAME") or "querybook"
    APP_VERSION = get_env_config("APP_VERSION") or "dev"
    BUILD_DATE = get_env_config("BUILD_DATE") or "Unknown"

    # Core
    PRODUCTION = os.environ.get("production", "false") == "true"
    PUBLIC_URL = get_env_config("PUBLIC_URL")
    FLASK_SECRET_KEY = get_env_config("FLASK_SECRET_KEY", optional=False)
    FLASK_CACHE_CONFIG = json.loads(get_env_config("FLASK_CACHE_CONFIG"))
    # Celery
    REDIS_URL = get_env_config("REDIS_URL", optional=False)

    # Search
    ELASTICSEARCH_HOST = get_env_config("ELASTICSEARCH_HOST", optional=False)
    ELASTICSEARCH_CONNECTION_TYPE = get_env_config("ELASTICSEARCH_CONNECTION_TYPE")

    # Lineage
    DATA_LINEAGE_BACKEND = get_env_config("DATA_LINEAGE_BACKEND")

    # Database
    DATABASE_CONN = get_env_config("DATABASE_CONN", optional=False)
    DATABASE_POOL_SIZE = int(get_env_config("DATABASE_POOL_SIZE"))
    DATABASE_POOL_RECYCLE = int(get_env_config("DATABASE_POOL_RECYCLE"))

    # Communications
    EMAILER_CONN = get_env_config("EMAILER_CONN")
    QUERYBOOK_SLACK_TOKEN = get_env_config("QUERYBOOK_SLACK_TOKEN")
    QUERYBOOK_EMAIL_ADDRESS = get_env_config("QUERYBOOK_EMAIL_ADDRESS")

    # Authentication
    AUTH_BACKEND = get_env_config("AUTH_BACKEND")
    LOGS_OUT_AFTER = int(get_env_config("LOGS_OUT_AFTER"))

    OAUTH_CLIENT_ID = get_env_config("OAUTH_CLIENT_ID")
    OAUTH_CLIENT_SECRET = get_env_config("OAUTH_CLIENT_SECRET")
    OAUTH_AUTHORIZATION_URL = get_env_config("OAUTH_AUTHORIZATION_URL")
    OAUTH_TOKEN_URL = get_env_config("OAUTH_TOKEN_URL")
    OAUTH_USER_PROFILE = get_env_config("OAUTH_USER_PROFILE")
    AZURE_TENANT_ID = get_env_config("AZURE_TENANT_ID")

    LDAP_CONN = get_env_config("LDAP_CONN")
    LDAP_USE_TLS = str(get_env_config("LDAP_USE_TLS")).lower() == "true"
    LDAP_USE_BIND_USER = str(get_env_config("LDAP_USE_BIND_USER")).lower() == "true"
    # For direct authentication
    LDAP_USER_DN = get_env_config("LDAP_USER_DN")
    # For searches using bind user
    LDAP_BIND_USER = get_env_config("LDAP_BIND_USER")
    LDAP_BIND_PASSWORD = get_env_config("LDAP_BIND_PASSWORD")
    LDAP_SEARCH = get_env_config("LDAP_SEARCH")
    LDAP_FILTER = get_env_config("LDAP_FILTER")
    LDAP_UID_FIELD = get_env_config("LDAP_UID_FIELD")
    # Configuration validation
    if LDAP_CONN is not None:
        if LDAP_USE_BIND_USER:
            if (
                LDAP_BIND_USER is None
                or LDAP_BIND_PASSWORD is None
                or LDAP_SEARCH is None
            ):
                raise ValueError(
                    "LDAP_BIND_USER, LDAP_BIND_PASSWORD and LDAP_SEARCH has to be set when using LDAP bind user connection"
                )
        elif LDAP_USER_DN is None:
            raise ValueError(
                "LDAP_USER_DN has to be set when using direct LDAP connection"
            )

    # Result Store
    RESULT_STORE_TYPE = get_env_config("RESULT_STORE_TYPE")

    STORE_BUCKET_NAME = get_env_config("STORE_BUCKET_NAME")
    STORE_PATH_PREFIX = get_env_config("STORE_PATH_PREFIX")
    STORE_MIN_UPLOAD_CHUNK_SIZE = int(get_env_config("STORE_MIN_UPLOAD_CHUNK_SIZE"))
    STORE_MAX_UPLOAD_CHUNK_NUM = int(get_env_config("STORE_MAX_UPLOAD_CHUNK_NUM"))
    STORE_MAX_READ_SIZE = int(get_env_config("STORE_MAX_READ_SIZE"))
    STORE_READ_SIZE = int(get_env_config("STORE_READ_SIZE"))
    S3_BUCKET_S3V4_ENABLED = get_env_config("S3_BUCKET_S3V4_ENABLED") == "true"
    AWS_REGION = get_env_config("AWS_REGION")

    DB_MAX_UPLOAD_SIZE = int(get_env_config("DB_MAX_UPLOAD_SIZE"))

    GOOGLE_CREDS = json.loads(get_env_config("GOOGLE_CREDS") or "null")

    # Logging
    LOG_LOCATION = get_env_config("LOG_LOCATION")
    LOG_DEBUG_LEVEL = str(get_env_config("LOG_DEBUG_LEVEL")).lower() == "true"

    # Table Upload (Experimental)
    TABLE_MAX_UPLOAD_SIZE = get_env_config("TABLE_MAX_UPLOAD_SIZE")
    TABLE_UPLOAD_S3_PATH = get_env_config("TABLE_UPLOAD_S3_PATH")
    if TABLE_UPLOAD_S3_PATH and not TABLE_UPLOAD_S3_PATH.endswith("/"):
        TABLE_UPLOAD_S3_PATH += "/"

    # DataOS
    DATAOS_OIDC_CLIENT_ID = get_env_config("OIDC_CLIENT_ID")
    DATAOS_OIDC_CLIENT_SECRET = get_env_config("OIDC_CLIENT_SECRET")
    DATAOS_BASE_URL = get_env_config_strip_slash("DATAOS_BASE_URL")
    DATAOS_MINERVA_QUERY_URL = get_env_config_strip_slash("MINERVA_QUERY_URL")
    DATAOS_APIKEY = get_env_config("DATAOS_APIKEY", optional=False)

    # EMail
    MAIL_SERVER = get_env_config("MAIL_SERVER")
    MAIL_PORT = int(get_env_config("MAIL_PORT"))
    MAIL_USE_TLS = get_env_config("MAIL_USE_TLS") == "true"
    MAIL_USE_SSL = get_env_config("MAIL_USE_SSL") == "true"
    MAIL_USERNAME = get_env_config("MAIL_USERNAME")
    MAIL_PASSWORD = get_env_config("MAIL_PASSWORD")
    MAIL_DEFAULT_SENDER = get_env_config("MAIL_DEFAULT_SENDER")
    MAIL_MAX_EMAILS = get_env_config("MAIL_MAX_EMAILS")
    MAIL_ASCII_ATTACHMENTS = get_env_config("MAIL_ASCII_ATTACHMENTS") == "true"
