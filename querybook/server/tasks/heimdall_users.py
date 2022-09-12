from app.flask_app import celery
from logic.schedule import with_task_logging
from lib.logger import get_logger
from app.db import DBSession
from app.auth.utils import (
    get_heimdall_users,
    update_admin_user_role_by_dataos_tags,
    get_heimdall_user_profile_img,
)
from env import QuerybookSettings
from logic.user import get_user_by_name, create_user, update_user

LOG = get_logger(__file__)


# TODO: Apply throttling
@celery.task(bind=True)
@with_task_logging()
def sync_users(*args, **kwargs):
    access_token = QuerybookSettings.DATAOS_APIKEY
    users = get_heimdall_users(access_token)
    create_count = 0
    update_count = 0
    with DBSession() as session:
        for user in users:
            type = user["type"]
            email = user["email"]
            username = user["username"]
            fullname = user["fullname"]
            tags = user["tags"]
            if type == "person" and email != "":
                qb_user = get_user_by_name(username)
                if qb_user:
                    # fullname or email changed?
                    if qb_user.fullname != fullname or qb_user.email != email:
                        update_user(
                            qb_user.id,
                            fullname=fullname if fullname is not None else username,
                            email=email,
                            session=session,
                        )
                        LOG.info(f"updated user ({qb_user.id, username, email})")
                        update_count += 1
                else:
                    # Get profile_img
                    profile_img = get_heimdall_user_profile_img(access_token, username)
                    qb_user = create_user(
                        username=username,
                        fullname=fullname if fullname is not None else username,
                        email=email,
                        profile_img=profile_img,
                        session=session,
                    )
                    LOG.info(f"created user ({qb_user.id, username, email})")
                    create_count += 1

                # Update role
                update_admin_user_role_by_dataos_tags(
                    qb_user.id, username, tags or [], session
                )

    LOG.info(f"*** created {create_count} users; updated {update_count} users ***")
