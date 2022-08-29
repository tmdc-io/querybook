from app.flask_app import celery
from logic.schedule import with_task_logging
from lib.logger import get_logger
from app.db import DBSession
from app.auth.utils import get_heimdall_users
from env import QuerybookSettings
from logic.user import get_user_by_name, create_user

LOG = get_logger(__file__)


# TODO: Apply throttling
@celery.task(bind=True)
@with_task_logging()
def create_users(*args, **kwargs):
    users = get_heimdall_users(QuerybookSettings.DATAOS_APIKEY)
    count = 0
    with DBSession() as session:
        for user in users:
            type = user["type"]
            email = user["email"]
            username = user["username"]
            fullname = user["fullname"]
            if type == "person" and email != "" and not get_user_by_name(username):
                q_user = create_user(
                    username=username,
                    fullname=fullname if fullname is not None else username,
                    email=email,
                    session=session,
                )
                LOG.info(f"created user ({q_user.id, username, email})")
                count += 1
    LOG.info(f"*** created {count} users ***")
