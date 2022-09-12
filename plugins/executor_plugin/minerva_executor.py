import re
from pyhive import presto
from pyhive.exc import DatabaseError, Error
from const.query_execution import QueryExecutionErrorType
from lib.query_executor.base_client import ClientBaseClass, CursorBaseClass
from lib.query_executor.base_executor import QueryExecutorBaseClass
from lib.query_executor.utils import get_parsed_syntax_error
from lib.query_executor.connection_string.helpers.common import (
    split_hostport,
    random_choice,
)
from lib.form import StructFormField, FormField
from logic.user import get_user_by_name
from env import QuerybookSettings, get_user_agent
from const.dataos import minerva_connection_regex, minerva_cluster_regex, minerva_language, minerva_executor_name
from lib.logger import get_logger

LOG = get_logger(__file__)

def_minerva_query_url = QuerybookSettings.DATAOS_MINERVA_QUERY_URL

def _parse_connection(connection_string: str):
    match = re.search(minerva_connection_regex, connection_string, )

    protocol = match.group(1)
    raw_hosts = match.group(2)
    parsed_hosts = [split_hostport(hostport) for hostport in raw_hosts.split(",")]
    hostname, port = random_choice(parsed_hosts, default=(None, None))

    return protocol, hostname, port


def get_minerva_error_dict(e):
    if hasattr(e, "args") and e.args[0] is not None:
        error_arg = e.args[0]
        if type(error_arg) is dict:
            return error_arg
    return None


class MinervaQueryExecutor(QueryExecutorBaseClass):
    @classmethod
    def _get_client(cls, client_setting):
        return MinervaClient(**client_setting)

    @classmethod
    def EXECUTOR_NAME(cls):
        return minerva_executor_name

    @classmethod
    def EXECUTOR_LANGUAGE(cls):
        return minerva_language

    @classmethod
    def EXECUTOR_TEMPLATE(cls):
        return StructFormField(
            apikey=FormField(
                required=False,
                hidden=True,
                helper="<p>Apikey to connect with DataOS Minerva. If empty, current user's <code>heimdall apikey</code> will be used.</p>",
            ),
            cluster=FormField(
                required=True,
                regex=minerva_cluster_regex,
                helper="<p>Minerva cluster name</p>",
            ),
            connection=FormField(
                required=False,
                regex=minerva_connection_regex,
                description=def_minerva_query_url,
                helper=f"<p>Connection to DataOS Minerva <br/><code>{def_minerva_query_url}</code></p>",
            ),
        )

    def _parse_exception(self, e):
        error_type = QueryExecutionErrorType.INTERNAL.value
        error_str = str(e)
        error_extracted = None

        try:
            if isinstance(e, Error):
                error_type = QueryExecutionErrorType.ENGINE.value
                error_dict = get_minerva_error_dict(e)
                if error_dict:
                    error_extracted = error_dict.get("message", None)
                    # In Presto, only context free syntax error are labelled as
                    # SYNTAX_ERROR, and context sensitive errors are user errors
                    # However in both cases errorLocation is provided
                    if "errorLocation" in error_dict:
                        return get_parsed_syntax_error(
                            error_extracted,
                            error_dict["errorLocation"].get("lineNumber", 1) - 1,
                            error_dict["errorLocation"].get("columnNumber", 1) - 1,
                        )

        except Exception:
            pass
        return error_type, error_str, error_extracted


class MinervaClient(ClientBaseClass):
    def __init__(
        self,
        cluster,
        apikey=None,
        connection=def_minerva_query_url,
        proxy_user=None,
        *args,
        **kwargs
    ):
        protocol, hostname, port = _parse_connection(connection)
        source = get_user_agent()
        if proxy_user:
            current_user = get_user_by_name(proxy_user)
            current_user_apikey = current_user.properties["heimdall"] if current_user else None
        else:
            current_user_apikey: None

        connection = presto.connect(
            protocol=protocol,
            host=hostname,
            port=port,
            username=proxy_user or None,
            password=apikey or current_user_apikey or QuerybookSettings.DATAOS_APIKEY,
            catalog=None,
            schema=None,
            source=source,
            session_props={"cluster-name": cluster},
            requests_kwargs={},
        )
        self._connection = connection
        super(MinervaClient, self).__init__()

    def cursor(self):
        return MinervaCursor(cursor=self._connection.cursor())


class MinervaCursor(CursorBaseClass):
    def __init__(self, cursor):
        self._cursor = cursor
        self._init_query_state_vars()

    def _init_query_state_vars(self):
        self._tracking_url = None
        self._percent_complete = 0

    def run(self, query: str):
        self._init_query_state_vars()
        self._cursor.execute(query)

    def cancel(self):
        self._cursor.cancel()

    def poll(self):
        poll_result = self._cursor.poll()
        # PyHive does not support presto async, Hence the hack
        status = self._cursor._state
        # Finished if status is not running or none
        completed = status not in (
            self._cursor._STATE_RUNNING,
            self._cursor._STATE_NONE,
        )

        if poll_result:
            self._update_percent_complete(poll_result)
            self._update_tracking_url(poll_result)

        return completed

    def get_one_row(self):
        return self._cursor.fetchone()

    def get_n_rows(self, n: int):
        return self._cursor.fetchmany(size=n)

    def get_columns(self):
        description = self._cursor.description
        if description is None:
            # Not a select query, no return
            return None
        else:
            columns = list(map(lambda d: d[0], description))
            return columns

    @property
    def tracking_url(self):
        return self._tracking_url

    @property
    def percent_complete(self):
        return self._percent_complete

    def _update_percent_complete(self, poll_result):
        stats = poll_result.get("stats", {})
        completed_splits = stats.get("completedSplits", 0)
        total_splits = max(stats.get("totalSplits", 1), 1)
        self._percent_complete = (completed_splits * 100) / total_splits

    def _update_tracking_url(self, poll_result):
        if self._tracking_url is None:
            # self._tracking_url = poll_result.get("infoUri", None)
            # TODO Update this to point to Gateway when the UI is ready there
            query_id = poll_result.get("id", None)
            self._tracking_url = f"{QuerybookSettings.DATAOS_BASE_URL}/workbench/query-track/{query_id}"
