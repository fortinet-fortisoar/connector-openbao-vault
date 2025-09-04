"""
Copyright start
MIT License
Copyright (c) 2025 Fortinet Inc
Copyright end
"""

from .operations import operations, _check_health
from connectors.core.connector import Connector, get_logger, ConnectorError

logger = get_logger('openbao-vault')


class OpenBaoVault(Connector):
    def execute(self, config, operation, operation_params, **kwargs):
        try:
            operation = operations.get(operation)
            return operation(config, operation_params)
        except Exception as err:
            logger.exception("An exception occurred [{}]".format(err))
            raise ConnectorError("An exception occurred [{}]".format(err))

    def check_health(self, config):
        try:
            _check_health(config)
        except Exception as e:
            raise ConnectorError(e)
