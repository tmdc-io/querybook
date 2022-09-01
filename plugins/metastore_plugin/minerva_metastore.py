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
from const.dataos import minerva_connection_regex, minerva_cluster_regex
from env import QuerybookSettings, get_env_config, get_env_config_strip_slash, get_user_agent
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


class MinervaMetadataLoader(BaseMetastoreLoader):
    def __init__(self, metastore_dict: Dict):
        connection = metastore_dict.get("metastore_params").get("connection") or def_minerva_query_url
        protocol, hostname, port = _parse_connection(connection)
        self.protocol = protocol
        self.hostname = hostname
        self.port = port
        self.source = get_user_agent()
        self.cluster = metastore_dict.get("metastore_params").get("cluster")
        self.username = QuerybookSettings.APP_NAME
        self.apikey = metastore_dict.get("metastore_params").get("apikey") or QuerybookSettings.DATAOS_APIKEY

        super(MinervaMetadataLoader, self).__init__(metastore_dict)

    @classmethod
    def get_metastore_params_template(cls):
        return StructFormField(
            apikey=FormField(
                required=False,
                hidden=True,
                helper="<p>Apikey to connect with DataOS Minerva. If empty, <code>DATAOS_APIKEY</code> will be used.</p>",
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

    def run_query(self, query: str):
        req_kwargs = {}

        connection = presto.connect(
            protocol=self.protocol,
            host=self.hostname,
            port=self.port,
            username=self.username,
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
            /* {get_user_agent()} */
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
            /* {get_user_agent()} */
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
            /* {get_user_agent()} */
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
