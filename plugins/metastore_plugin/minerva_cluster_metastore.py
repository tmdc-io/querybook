import os
import re
import time
from pyhive import presto
from pyhive.exc import DatabaseError
from typing import Dict, List, Tuple

from lib.query_executor.connection_string.helpers.common import (
    split_hostport,
    random_choice,
)
from lib.form import StructFormField, FormField
from lib.metastore.base_metastore_loader import (
    BaseMetastoreLoader,
    DataTable,
    DataColumn,
)

from env import QuerybookSettings, get_env_config, get_env_config_strip_slash
from lib.logger import get_logger

LOG = get_logger(__file__)

CONST_MINERVA_QUERY_URL = "MINERVA_QUERY_URL"
connection_regex = r"^(http|https):\/\/([\w.-]+(?:\:\d+)?(?:,[\w.-]+(?:\:\d+)?)*)(\/\w+)?(\/\w+)?(\?[\w.-]+=[\w.-]+(?:&[\w.-]+=[\w.-]+)*)?$"
apikey_regex = r"^[A-Za-z0-9=]+$"
cluster_regex = r"^[A-Za-z0-9]+$"


def _parse_connection(connection_string: str):
    match = re.search(connection_regex, connection_string, )

    protocol = match.group(1)
    raw_hosts = match.group(2)
    parsed_hosts = [split_hostport(hostport) for hostport in raw_hosts.split(",")]
    hostname, port = random_choice(parsed_hosts, default=(None, None))

    return protocol, hostname, port


class MinervaClusterMetadataLoader(BaseMetastoreLoader):
    def __init__(self, metastore_dict: Dict):
        connection = metastore_dict.get("metastore_params").get("connection")
        protocol, hostname, port = _parse_connection(connection)
        self.protocol = protocol
        self.hostname = hostname
        self.port = port
        self.source = "{0}/{1}".format(
            get_env_config("QUERYBOOK_APPNAME") or "Querybook",
            get_env_config("QUERYBOOK_VERSION") or "dev"
        )
        self.cluster = metastore_dict.get("metastore_params").get("cluster")
        self.apikey = metastore_dict.get("metastore_params").get("apikey")

        super(MinervaMetadataLoader, self).__init__(metastore_dict)

    @classmethod
    def get_metastore_params_template(cls):
        def_minerva_query_url = get_env_config_strip_slash(CONST_MINERVA_QUERY_URL)
        return StructFormField(
            connection=FormField(
                required=True,
                regex=connection_regex,
                description=def_minerva_query_url,
                helper=f"<p>Connection to minerva query engine. It should look like this: <br/><code>{def_minerva_query_url}</code></p>",
            ),
            apikey=FormField(
                required=True,
                regex=apikey_regex,
                helper="<p>Apikey to connect with Minerva query engine</p>",
            ),
            cluster=FormField(
                required=True,
                regex=cluster_regex,
                helper="<p>Minerva cluster name</p>",
            )
        )

    def run_query(self, query: str):
        req_kwargs = {}

        connection = presto.connect(
            protocol=self.protocol,
            host=self.hostname,
            port=self.port,
            # username=self.apikey, # TODO: look at it again?
            password=self.apikey,
            source=self.source,
            session_props={"cluster-name": self.cluster},
            requests_kwargs=req_kwargs,
        )

        cursor = connection.cursor()
        try:
            LOG.debug(f"run_query: {query}")
            cursor.execute(query)
            columns = list(map(lambda d: d[0], cursor.description))
            rows = cursor.fetchall()
        except DatabaseError as e:
            LOG.error("***** ERROR {0}".format(e))
            raise e

        return columns, rows

    def get_all_schema_names(self) -> List[str]:
        query = f"""
            /* get_all_schema_names() cluster:{self.cluster} */
            SELECT DISTINCT CONCAT(table_cat, '.', table_schem)
            FROM system.jdbc.columns
            WHERE
                table_schem NOT IN ('pg_catalog', 'information_schema', 'definitions')
                AND table_cat NOT IN ('system')
        """
        columns, rows = self.run_query(query)
        schemas = [row[0] for row in rows]
        LOG.info(f"[Minerva] get_all_schema_names: schemas: {schemas}")
        return schemas

    def get_all_table_names_in_schema(self, schema_name: str) -> List[str]:
        [catalog, schema] = schema_name.split(".")
        query = f"""
            /* get_all_table_names_in_schema() cluster:{self.cluster} */
            SELECT DISTINCT table_name
            FROM system.jdbc.columns
            WHERE table_cat = '{catalog}' AND table_schem = '{schema}'
        """
        columns, rows = self.run_query(query)
        tables = [row[0] for row in rows]
        LOG.debug(f"[Minerva] get_all_table_names_in_schema: tables: {tables}")
        return tables

    def get_table_and_columns(
            self, schema_name: str, table_name: str
    ) -> Tuple[DataTable, List[DataColumn]]:
        [catalog, schema] = schema_name.split(".")
        query = f"""
            /* get_table_and_columns() cluster:{self.cluster} */
            SELECT
                table_cat,
                table_schem,
                table_name,
                column_Name,
                type_name,
                remarks,
                data_type,
                column_size
            FROM system.jdbc.columns
            WHERE table_cat = '{catalog}' AND table_schem = '{schema}' AND table_name = '{table_name}'
        """
        columns, rows = self.run_query(query)

        table = DataTable(
            name=table_name,
            table_created_at=int(time.time()),
            table_updated_at=int(time.time()),
        )

        columns = [DataColumn(row[3], row[4], row[5]) for row in rows]

        return table, columns
