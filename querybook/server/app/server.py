import os
from flask import send_file, abort

from app import auth

# from app.datasource import register, abort_request
from app.flask_app import flask_app, limiter
from const.path import WEBAPP_INDEX_PATH
from env import QuerybookSettings


import datasources
import datasources_socketio

auth.init_app(flask_app)
datasources
datasources_socketio


# @register("/querybook/<path:ignore>")
# @limiter.exempt
# def datasource_four_oh_four(*args, **kwargs):
#     abort_request(404)


@flask_app.route("/querybook/ping/")
@limiter.exempt
def get_health_check():
    """This is a health check endpoint"""
    if os.path.exists("/tmp/querybook/deploying"):
        abort(503)
    return "pong"


@flask_app.route("/querybook/")
@flask_app.route("/querybook/<path:ignore>")
@flask_app.errorhandler(404)
@limiter.exempt
def main(ignore=None):
    return send_file(WEBAPP_INDEX_PATH, mimetype="text/html")


@flask_app.after_request
def apply_caching(response):
    response.headers["x-version"] = QuerybookSettings.APP_VERSION
    response.headers["x-build-date"] = QuerybookSettings.BUILD_DATE
    return response
