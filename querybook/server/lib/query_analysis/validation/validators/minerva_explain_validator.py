from typing import List
from pyhive.exc import Error as PyHiveError
from lib.query_analysis.validation.base_query_validator import (
    QueryValidationResult,
)
from lib.utils.utils import Timeout
from const.dataos import minerva_language
from .presto_explain_validator import (
    PrestoExplainValidator,
)


class MinervaExplainValidator(PrestoExplainValidator):
    def languages(self):
        return [minerva_language]

    def validate(
        self,
        query: str,
        uid: int,  # who is doing the syntax check
        engine_id: int,  # which engine they are checking against
    ) -> List[QueryValidationResult]:
        validation_errors = []
        (
            validation_statements,
            statement_start_locations,
        ) = self._convert_query_to_explains(query)
        statement_idx = 0
        with Timeout(60, "Query validation took too long to finish"):
            while statement_idx < len(validation_statements):
                try:
                    self._run_validation_statement(
                        validation_statements[statement_idx], engine_id, uid
                    )
                except PyHiveError as exc:
                    presto_syntax_error = self._get_semantic_error_from_exc(exc)
                    if presto_syntax_error:
                        error_line, error_ch, error_msg = presto_syntax_error
                        validation_errors.append(
                            self._map_statement_error_to_query(
                                statement_idx,
                                statement_start_locations,
                                error_line,
                                error_ch,
                                error_msg,
                            )
                        )

                statement_idx += 1
        return validation_errors
