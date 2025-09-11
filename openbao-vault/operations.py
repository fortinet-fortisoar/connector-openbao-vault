"""
Copyright start
MIT License
Copyright (c) 2025 Fortinet Inc
Copyright end
"""

import requests
import os
from connectors.core.connector import get_logger, ConnectorError

logger = get_logger('openbao-vault')


class OpenBaoVault:
    def __init__(self, config):
        self.token = config.get('token')
        self.namespace = config.get('namespace')
        self.secret_name = config.get('secret_name')
        self.base_url = config['server_url'].strip("/")
        if not self.base_url.startswith('https://') and not self.base_url.startswith('http://'):
            self.base_url = 'https://{0}/v1/{1}/'.format(self.base_url, self.secret_name)
        else:
            self.base_url = self.base_url + '/v1/{0}/'.format(self.secret_name)
        self.verify_ssl = config.get('verify_ssl')
        self.headers = {"X-Vault-Token": self.token, "X-Vault-Namespace": self.namespace}

    def make_api_call(self, endpoint, method='GET', payload=None, params=None):
        service_endpoint = self.base_url + endpoint
        try:
            response = requests.request(method, service_endpoint, json=payload,
                                        headers=self.headers, params=params,
                                        verify=self.verify_ssl)
            if response.ok or response.status_code == 204:
                logger.info('Successfully got response for url {0}'.format(service_endpoint))
                if 'json' in str(response.headers):
                    return response.json()
                else:
                    return response
            else:
                logger.error("{0}".format(response.status_code))
                raise ConnectorError("{0}:{1}".format(response.status_code, response.text))
        except requests.exceptions.SSLError:
            raise ConnectorError('SSL certificate validation failed')
        except requests.exceptions.ConnectTimeout:
            raise ConnectorError('The request timed out while trying to connect to the server')
        except requests.exceptions.ReadTimeout:
            raise ConnectorError(
                'The server did not send any data in the allotted amount of time')
        except requests.exceptions.ConnectionError:
            raise ConnectorError('Invalid Credentials')
        except Exception as err:
            raise ConnectorError(str(err))


def get_password(config, params):
    try:
        openbao = OpenBaoVault(config)
        endpoint = "metadata"
        retrieve_creds = openbao.make_api_call(endpoint, method='LIST')
        return retrieve_creds
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def fetch_func(config, item):
    openbao = OpenBaoVault(config)
    endpoint = "metadata/{0}".format(item)
    response = openbao.make_api_call(endpoint, method='LIST')
    resp = response.get('data')['keys']
    resp = [item + it for it in resp]
    return resp


def get_creds(config, params, items, credentials = []):
    openbao = OpenBaoVault(config)
    for item in items:
        if item.endswith("/"):
            sub_items = fetch_func(config, item)
            get_creds(config, params, sub_items, credentials)
        else:
            endpoint = "data/{0}".format(item)
            response = openbao.make_api_call(endpoint, method='GET')
            res = response.get('data')['data']
            base_path = os.path.basename(item)
            credentials.append({base_path: res})
    return credentials


def get_credentials(config, params):
    openbao = OpenBaoVault(config)
    endpoint = "metadata"
    response = openbao.make_api_call(endpoint, method='LIST')
    try:
        items = response.get('data')['keys']
    except:
        items = response.get('errors')
    credentials = get_creds(config, params, items)
    formatted_output = []
    for secrets in credentials:
        for key, value in secrets.items():
            formatted_output.append(
                {
                    "key": key,
                    "display_name": key
                }
            )
    return formatted_output


def get_credentials_details(config, params):
    openbao = OpenBaoVault(config)
    endpoint = "metadata"
    Object = params.get('secret_id')
    response = openbao.make_api_call(endpoint, method='LIST')
    try:
        items = response.get('data')['keys']
    except:
        items = response.get('errors')
    formatted_output = []
    credentials = get_creds(config, params, items)
    for secrets in credentials:
        if Object in secrets:
            for key, value in secrets[Object].items():
                formatted_output.append(
                    {
                        "field_name": key,
                        "value": "*****"
                    }
                )
            return formatted_output
    return formatted_output


def get_credential(config, params):
    openbao = OpenBaoVault(config)
    endpoint = "metadata"
    Object = params.get('secret_id')
    response = openbao.make_api_call(endpoint, method='LIST')
    try:
        items = response.get('data')['keys']
    except:
        items = response.get('errors')
    credentials = get_creds(config, params, items)
    attribute_name = params.get('attribute_name')
    for secrets in credentials:
        if Object in secrets:
            for key, value in secrets[Object].items():
                if attribute_name == key:
                    return {
                        "password": value
                    }


def _check_health(config):
    try:
        response = get_password(config, params={})
        if response:
            return True
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


operations = {
    'get_credentials': get_credentials,
    'get_credentials_details': get_credentials_details,
    'get_credential': get_credential
}
