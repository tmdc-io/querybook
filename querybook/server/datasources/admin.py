from flask_login import current_user
import re
from app.datasource import register, admin_only, api_assert, RequestException
from app.db import DBSession
from const.admin import AdminOperation, AdminItemType
from const.dataos import minerva_language, minerva_executor_name, minerva_cluster_regex
from datasources.admin_audit_log import with_admin_audit_log
from env import QuerybookSettings

from lib.engine_status_checker import (
    ALL_ENGINE_STATUS_CHECKERS,
    get_engine_checker_class,
)
from lib.metastore.all_loaders import ALL_METASTORE_LOADERS
from lib.table_upload.exporter.exporter_factory import ALL_TABLE_UPLOAD_EXPORTER_BY_NAME
from lib.query_executor.all_executors import (
    get_flattened_executor_template,
    get_executor_class,
)
from lib.query_analysis.validation.all_validators import ALL_QUERY_VALIDATORS_BY_NAME
from logic import admin as logic
from logic import user as user_logic
from logic import environment as environment_logic
from logic import schedule as schedule_logic
from logic import metastore as metastore_logic
from logic import demo as demo_logic
from models.admin import Announcement, QueryMetastore, QueryEngine, AdminAuditLog
from models.schedule import TaskSchedule
from lib.logger import get_logger

LOG = get_logger(__file__)


@register(
    "/announcement/",
    methods=["GET"],
)
def get_announcements():
    return logic.get_admin_announcements()


# ADMIN ONLY APIs
@register(
    "/admin/announcement/",
    methods=["GET"],
)
@admin_only
def get_announcements_admin():
    announcements = Announcement.get_all()
    announcements_dict = [
        announcement.to_dict_admin() for announcement in announcements
    ]
    return announcements_dict


@register("/admin/announcement/", methods=["POST"])
@admin_only
@with_admin_audit_log(AdminItemType.Announcement, AdminOperation.CREATE)
def create_announcement(
    message,
    url_regex="",
    can_dismiss=True,
    active_from=None,
    active_till=None,
):
    with DBSession() as session:
        announcement = Announcement.create(
            {
                "uid": current_user.id,
                "url_regex": url_regex,
                "can_dismiss": can_dismiss,
                "message": message,
                "active_from": active_from,
                "active_till": active_till,
            },
            session=session,
        )
        announcement_dict = announcement.to_dict_admin()

    return announcement_dict


@register("/admin/announcement/<int:id>/", methods=["PUT"])
@admin_only
@with_admin_audit_log(AdminItemType.Announcement, AdminOperation.UPDATE)
def update_announcement(id, **kwargs):
    with DBSession() as session:
        announcement = Announcement.update(
            id=id,
            fields={
                **kwargs,
                "uid": current_user.id,
            },
            field_names=[
                "uid",
                "message",
                "url_regex",
                "can_dismiss",
                "active_from",
                "active_till",
            ],
            session=session,
        )
        announcement_dict = announcement.to_dict_admin()
    return announcement_dict


@register("/admin/announcement/<int:id>/", methods=["DELETE"])
@admin_only
@with_admin_audit_log(AdminItemType.Announcement, AdminOperation.DELETE)
def delete_announcement(id):
    Announcement.delete(id)


@register("/admin/query_engine_template/", methods=["GET"])
@admin_only
def get_all_query_engines_templates():
    return get_flattened_executor_template()


@register("/admin/query_engine_status_checker/", methods=["GET"])
@admin_only
def get_query_engine_status_checkers():
    return [checker.NAME() for checker in ALL_ENGINE_STATUS_CHECKERS]


@register(
    "/admin/query_engine/",
    methods=["GET"],
)
@admin_only
def get_all_query_engines_admin():
    with DBSession() as session:
        engines = QueryEngine.get_all(session=session)
        engines_dict = [engine.to_dict_admin() for engine in engines]
        return engines_dict


@register(
    "/admin/query_engine/",
    methods=["POST"],
)
@admin_only
@with_admin_audit_log(AdminItemType.QueryEngine, AdminOperation.CREATE)
def create_query_engine(
    name,
    language,
    executor,
    executor_params,
    feature_params,
    description=None,
    metastore_id=None,
):
    with DBSession() as session:
        query_engine = QueryEngine.create(
            {
                "name": name,
                "description": description,
                "language": language,
                "executor": executor,
                "executor_params": executor_params,
                "feature_params": feature_params,
                "metastore_id": metastore_id,
            },
            session=session,
        )
        query_engine_dict = query_engine.to_dict_admin()

    return query_engine_dict


@register(
    "/admin/query_engine/connection/",
    methods=["GET"],
)
@admin_only
def test_query_engine_connection(
    name,
    language,
    executor,
    executor_params,
    feature_params,
):
    status_checker = get_engine_checker_class(feature_params["status_checker"])
    executor_class = get_executor_class(language, executor)
    pseudo_engine_dict = {
        "name": name,
        "language": language,
        "executor": executor,
        "executor_params": executor_params,
        "feature_params": feature_params,
    }

    return status_checker.perform_check_with_executor(
        executor_class, executor_params, pseudo_engine_dict
    )


@register(
    "/admin/query_engine/<int:id>/",
    methods=["PUT"],
)
@admin_only
@with_admin_audit_log(AdminItemType.QueryEngine, AdminOperation.UPDATE)
def update_query_engine(id, **fields_to_update):
    with DBSession() as session:
        query_engine = QueryEngine.update(
            id,
            fields_to_update,
            field_names=[
                "name",
                "description",
                "language",
                "executor",
                "executor_params",
                "feature_params",
                "metastore_id",
                "deleted_at",
                "status_checker",
            ],
            session=session,
        )
        query_engine_dict = query_engine.to_dict_admin()
        return query_engine_dict


@register(
    "/admin/query_engine/<int:id>/",
    methods=["DELETE"],
)
@admin_only
@with_admin_audit_log(AdminItemType.QueryEngine, AdminOperation.DELETE)
def delete_query_engine(
    id,
):
    logic.delete_query_engine_by_id(id)


@register(
    "/admin/query_engine/<int:id>/recover/",
    methods=["POST", "PUT"],
)
@admin_only
@with_admin_audit_log(AdminItemType.QueryEngine, AdminOperation.UPDATE)
def recover_query_engine(
    id,
):
    logic.recover_query_engine_by_id(id)


@register(
    "/admin/query_engine/name/<name>/recover/",
    methods=["PUT"],
)
@admin_only
@with_admin_audit_log(AdminItemType.QueryEngine, AdminOperation.UPDATE)
def recover_query_engine_by_name(
    name,
):
    logic.recover_query_engine_by_name(name)


@register(
    "/admin/query_metastore_loader/",
    methods=["GET"],
)
@admin_only
def get_all_query_metastore_loaders_admin():
    return [
        loader_class.serialize_loader_class() for loader_class in ALL_METASTORE_LOADERS
    ]


@register(
    "/admin/query_metastore/",
    methods=["GET"],
)
@admin_only
def get_all_query_metastores_admin():

    with DBSession() as session:
        metastores = logic.get_all_query_metastore(session=session)
        metastores_dict = [metastore.to_dict_admin() for metastore in metastores]
        return metastores_dict

    return []


@register(
    "/admin/query_metastore/",
    methods=["POST"],
)
@admin_only
@with_admin_audit_log(AdminItemType.QueryMetastore, AdminOperation.CREATE)
def create_metastore(
    name,
    metastore_params,
    loader,
    acl_control=None,
):
    with DBSession() as session:
        # TODO: validate executor params
        metastore = QueryMetastore.create(
            {
                "name": name,
                "metastore_params": metastore_params,
                "loader": loader,
                "acl_control": acl_control,
            },
            session=session,
        )
        metastore_dict = metastore.to_dict_admin()
        return metastore_dict


@register(
    "/admin/query_metastore/<int:id>/",
    methods=["PUT"],
)
@admin_only
@with_admin_audit_log(AdminItemType.QueryMetastore, AdminOperation.UPDATE)
def update_metastore(
    id,
    **fields,
):
    with DBSession() as session:
        metastore = QueryMetastore.update(
            id=id,
            fields=fields,
            field_names=["name", "loader", "metastore_params", "acl_control"],
            update_callback=lambda m: logic.sync_metastore_schedule_job(
                m.id, session=session
            ),
            session=session,
        )
        metastore_dict = metastore.to_dict_admin()
        return metastore_dict


@register(
    "/admin/query_metastore/<int:id>/schedule/",
    methods=["POST"],
)
@admin_only
def create_metastore_schedule(
    id,
    cron,
):
    with DBSession() as session:
        return logic.create_query_metastore_update_schedule(
            metastore_id=id, cron=cron, session=session
        )


@register(
    "/admin/query_metastore/<int:id>/recover/",
    methods=["PUT"],
)
@admin_only
@with_admin_audit_log(AdminItemType.QueryMetastore, AdminOperation.UPDATE)
def recover_metastore(
    id,
):
    logic.recover_query_metastore_by_id(id)


@register(
    "/admin/query_metastore/name/<name>/recover/",
    methods=["PUT"],
)
@admin_only
@with_admin_audit_log(AdminItemType.QueryMetastore, AdminOperation.UPDATE)
def recover_metastore_by_name(
    name,
):
    logic.recover_query_metastore_by_name(name)


@register(
    "/admin/query_metastore/<int:id>/",
    methods=["DELETE"],
)
@admin_only
@with_admin_audit_log(AdminItemType.QueryMetastore, AdminOperation.DELETE)
def delete_metastore(
    id,
):
    logic.delete_query_metastore_by_id(id)


@register(
    "/admin/user_role/",
    methods=["GET"],
)
@admin_only
def get_all_user_role_admin():
    with DBSession() as session:
        return user_logic.get_all_user_role(session=session)


@register(
    "/admin/user_role/",
    methods=["POST"],
)
@admin_only
@with_admin_audit_log(AdminItemType.Admin, AdminOperation.CREATE)
def create_user_role(uid, role):
    with DBSession() as session:
        return user_logic.create_user_role(uid=uid, role=role, session=session)


@register(
    "/admin/user_role/<int:id>/",
    methods=["DELETE"],
)
@admin_only
@with_admin_audit_log(AdminItemType.Admin, AdminOperation.DELETE)
def delete_user_role(
    id,
):
    user_logic.delete_user_role(id)


@register("/admin/environment/", methods=["GET"])
def get_all_environments_admin():
    return environment_logic.get_all_environment(include_deleted=True)


@register("/admin/environment/", methods=["POST"])
@admin_only
@with_admin_audit_log(AdminItemType.Environment, AdminOperation.CREATE)
def create_environment(
    name,
    description=None,
    image=None,
    public=None,
    hidden=None,
    deleted_at=None,
    shareable=None,
):
    return environment_logic.create_environment(
        name=name,
        description=description,
        image=image,
        public=public,
        hidden=hidden,
        deleted_at=deleted_at,
        shareable=shareable,
    )


@register("/admin/environment/<int:id>/", methods=["PUT"])
@admin_only
@with_admin_audit_log(AdminItemType.Environment, AdminOperation.UPDATE)
def update_environment(id, **fields_to_update):
    return environment_logic.update_environment(
        id=id,
        **fields_to_update,
    )


@register(
    "/admin/environment/<int:id>/recover/",
    methods=["PUT"],
)
@admin_only
def recover_environment(
    id,
):
    environment_logic.recover_environment_by_id(id)


@register(
    "/admin/environment/name/<name>/recover/",
    methods=["PUT"],
)
@admin_only
def recover_environment_by_name(
    name,
):
    environment_logic.recover_environment_by_name(name)


@register(
    "/admin/environment/<int:id>/",
    methods=["DELETE"],
)
@admin_only
@with_admin_audit_log(AdminItemType.Environment, AdminOperation.DELETE)
def delete_environment(
    id,
):
    environment_logic.delete_environment_by_id(id)


@register("/admin/environment/<int:id>/users/", methods=["GET"])
@admin_only
def get_users_in_environment(
    id,
    limit,
    offset,
):
    with DBSession() as session:
        return environment_logic.get_users_in_environment(
            id, offset, limit, session=session
        )


@register("/admin/environment/<int:id>/user/<int:uid>/", methods=["POST", "PUT"])
@admin_only
@with_admin_audit_log(AdminItemType.Environment, AdminOperation.UPDATE)
def add_user_to_environment(id, uid):
    environment_logic.add_user_to_environment(uid, id)


@register("/admin/environment/<int:id>/user/<int:uid>/", methods=["DELETE"])
@admin_only
@with_admin_audit_log(AdminItemType.Environment, AdminOperation.UPDATE)
def remove_user_from_environment(id, uid):
    environment_logic.remove_user_to_environment(uid, id)


@register("/admin/environment/<int:id>/query_engine/", methods=["GET"])
@admin_only
def get_query_engine_in_environment(id):
    return logic.get_query_engines_by_environment(id, ordered=True)


@register(
    "/admin/environment/<int:id>/query_engine/<int:engine_id>/",
    methods=["POST", "PUT"],
)
@admin_only
@with_admin_audit_log(AdminItemType.Environment, AdminOperation.UPDATE)
def add_query_engine_to_environment(id, engine_id):
    return logic.add_query_engine_to_environment(id, engine_id)


@register(
    "/admin/environment/<int:id>/query_engine/<int:from_index>/<int:to_index>/",
    methods=["POST", "PUT"],
)
@admin_only
@with_admin_audit_log(AdminItemType.Environment, AdminOperation.UPDATE)
def swap_query_engine_order_in_environment(id, from_index, to_index):
    logic.swap_query_engine_order_in_environment(id, from_index, to_index)


@register(
    "/admin/environment/<int:id>/query_engine/<int:engine_id>/", methods=["DELETE"]
)
@admin_only
@with_admin_audit_log(AdminItemType.Environment, AdminOperation.UPDATE)
def remove_query_engine_from_environment(id, engine_id):
    logic.remove_query_engine_from_environment(id, engine_id)


"""
    ---------------------------------------------------------------------------------------------------------
    API ACCESS TOKEN
    ---------------------------------------------------------------------------------------------------------
"""


@register(
    "/admin/api_access_token/<token_id>/",
    methods=["PUT"],
)
@admin_only
def update_api_access_token_admin(token_id, enabled=False):
    """
    Allow admins to enable/disable API Access Tokens
    """
    uid = current_user.id
    return logic.update_api_access_token(uid, token_id, enabled)


@register(
    "/admin/api_access_tokens/",
    methods=["GET"],
)
@admin_only
def get_api_access_tokens_admin():
    """
    Returns all API Access Tokens
    """
    return logic.get_api_access_tokens()


@register("/admin/demo_set_up/", methods=["POST"])
@admin_only
def exec_demo_set_up():
    with DBSession() as session:
        environment = environment_logic.create_environment(
            name="demo_environment",
            description="Demo environment",
            image="",
            public=True,
            commit=False,
            session=session,
        )

        local_db_conn = "sqlite:///demo/demo_data.db"
        metastore_id = QueryMetastore.create(
            {
                "name": "demo_metastore",
                "metastore_params": {
                    "connection_string": local_db_conn,
                },
                "loader": "SqlAlchemyMetastoreLoader",
                "acl_control": {},
            },
            commit=False,
            session=session,
        ).id

        engine_id = QueryEngine.create(
            {
                "name": "sqlite",
                "description": "SQLite Engine",
                "language": "sqlite",
                "executor": "sqlalchemy",
                "executor_params": {
                    "connection_string": local_db_conn,
                },
                "environment_id": environment.id,
                "metastore_id": metastore_id,
            },
            commit=False,
            session=session,
        ).id

        logic.add_query_engine_to_environment(
            environment.id, engine_id, commit=False, session=session
        )

        task_schedule_id = TaskSchedule.create(
            {
                "name": "update_metastore_{}".format(metastore_id),
                "task": "tasks.update_metastore.update_metastore",
                "cron": "0 0 * * *",
                "args": [metastore_id],
                "task_type": "prod",
                "enabled": True,
            },
            # commit=False,
            session=session,
        ).id
        schedule_logic.run_and_log_scheduled_task(
            scheduled_task_id=task_schedule_id, wait_to_finish=True, session=session
        )

        golden_table = metastore_logic.get_table_by_name(
            schema_name="main",
            name="world_happiness_2019",
            metastore_id=metastore_id,
            session=session,
        )
        if golden_table:
            metastore_logic.update_table(
                id=golden_table.id, golden=True, session=session
            )
            metastore_logic.update_table_information(
                data_table_id=golden_table.id,
                description="The World Happiness Report is a landmark survey of the state of global happiness. The first report was published in 2012, the second in 2013, the third in 2015, and the fourth in the 2016 Update. The World Happiness 2017, which ranks 155 countries by their happiness levels, was released at the United Nations at an event celebrating International Day of Happiness on March 20th. The report continues to gain global recognition as governments, organizations and civil society increasingly use happiness indicators to inform their policy-making decisions. Leading experts across fields – economics, psychology, survey analysis, national statistics, health, public policy and more – describe how measurements of well-being can be used effectively to assess the progress of nations. The reports review the state of happiness in the world today and show how the new science of happiness explains personal and national variations in happiness.",
                session=session,
            )
            demo_logic.create_demo_table_stats(
                table_id=golden_table.id, uid=current_user.id, session=session
            )
            score_column = metastore_logic.get_column_by_name(
                name="Score", table_id=golden_table.id, session=session
            )
            demo_logic.create_demo_table_column_stats(
                column_id=score_column.id, uid=current_user.id, session=session
            )

        schedule_logic.run_and_log_scheduled_task(
            scheduled_task_id=task_schedule_id, session=session
        )

        demo_logic.create_demo_lineage(metastore_id, current_user.id, session=session)

        data_doc_id = demo_logic.create_demo_data_doc(
            environment_id=environment.id,
            engine_id=engine_id,
            uid=current_user.id,
            session=session,
        )

        if data_doc_id:
            session.commit()

            return {
                "environment": environment.name,
                "data_doc_id": data_doc_id,
            }


admin_item_type_values = set(item.value for item in AdminItemType)


@register("/admin/audit_log/", methods=["GET"])
@admin_only
def get_admin_audit_logs(
    item_type=None,
    item_id=None,
    offset=0,
    limit=10,
):
    api_assert(limit < 200)
    api_assert(item_type is None or item_type in admin_item_type_values)

    filters = {}
    if item_type is not None:
        filters["item_type"] = item_type
    if item_id is not None:
        filters["item_id"] = item_id

    return AdminAuditLog.get_all(
        **filters, limit=limit, offset=offset, order_by="id", desc=True
    )


@register("/admin/querybook_config/", methods=["GET"])
@admin_only
def get_admin_config():
    return {
        key: getattr(QuerybookSettings, key)
        for key in dir(QuerybookSettings)
        if not key.startswith("__")
    }


@register("/admin/table_upload/exporter/", methods=["GET"])
@admin_only
def get_admin_table_upload_exporters():
    return list(ALL_TABLE_UPLOAD_EXPORTER_BY_NAME.keys())


@register("/admin/query_validator/", methods=["GET"])
@admin_only
def get_admin_query_validators():
    return list(ALL_QUERY_VALIDATORS_BY_NAME.values())


@register("/admin/minerva_set_up/", methods=["POST"])
@admin_only
def exec_minerva_set_up(
    cluster_name, environment_name, metastore_name, engine_name, **kwargs
):
    if not re.match(minerva_cluster_regex, cluster_name):
        raise RequestException(
            f"cluster_name={cluster_name} must match {minerva_cluster_regex}", 400
        )

    # environment_name pattern
    # ref: webapp/components/AppAdmin => environmentSchema
    environment_regex = r"^[a-z_0-9]+$"
    if not re.match(environment_regex, environment_name):
        raise RequestException(
            f"environment_name={environment_name} must match {environment_regex}", 400
        )

    # apikey = apikey or QuerybookSettings.DATAOS_APIKEY
    with DBSession() as session:
        # Environment
        environment = environment_logic.get_environment_by_name(environment_name)
        if environment is None:
            environment = environment_logic.create_environment(
                name=environment_name,
                description=environment_name,
                image="",
                public=True,
                commit=False,
                session=session,
            )
        else:
            raise RequestException(
                f"environment={environment_name} already exists", 400
            )

        # Metastore
        metastore = logic.get_query_metastore_by_name(metastore_name)
        if metastore is None:
            metastore = QueryMetastore.create(
                {
                    "name": metastore_name,
                    "metastore_params": {
                        # "apikey": apikey,
                        "cluster": cluster_name,
                    },
                    "loader": "MinervaMetadataLoader",
                    "acl_control": {},
                },
                commit=False,
                session=session,
            )
        else:
            raise RequestException(f"metastore={metastore_name} already exists", 400)

        # Engine
        engine = logic.get_query_engine_by_name(engine_name)
        if engine is None:
            engine = QueryEngine.create(
                {
                    "name": engine_name,
                    "description": engine_name,
                    "language": minerva_language,
                    "executor": minerva_executor_name,
                    "executor_params": {
                        # "apikey": apikey,
                        "cluster": cluster_name,
                    },
                    "feature_params": {"status_checker": "SelectOneChecker"},
                    "environment_id": environment.id,
                    "metastore_id": metastore.id,
                },
                commit=False,
                session=session,
            )
        else:
            raise RequestException(f"engine={metastore_name} already exists", 400)

        logic.add_query_engine_to_environment(
            environment.id, engine.id, commit=False, session=session
        )

        task_schedule = TaskSchedule.create(
            {
                "name": "{}_update_metastore_{}".format(metastore_name, metastore.id),
                "task": "tasks.update_metastore.update_metastore",
                "cron": "0 0 * * *",
                "args": [metastore.id],
                "task_type": "prod",
                "enabled": True,
            },
            commit=False,
            session=session,
        )

        schedule_logic.run_and_log_scheduled_task(
            scheduled_task_id=task_schedule.id, wait_to_finish=False, session=session
        )

        session.commit()

        return {
            "environment": environment,
            "cluster_name": cluster_name,
            "metastore": metastore,
            "engine": engine,
            "task_schedule": task_schedule,
        }
