# -*- coding: utf-8 -*-
"""
    Copyright (C) 2017 Sebastian Golasch (plugin.video.netflix)
    Copyright (C) 2018 Caphm (original implementation module)
    Copyright (C) 2020 Stefano Gottardo
    MSL requests

    SPDX-License-Identifier: MIT
    See LICENSES/MIT.md for more information.
"""
import base64
import json
import socket
import sys
import time
import zlib

import requests.exceptions as req_exceptions
from requests.adapters import HTTPAdapter, DEFAULT_POOLBLOCK
from urllib3 import PoolManager, HTTPConnectionPool, HTTPSConnectionPool

import resources.lib.common as common
from resources.lib.common.exceptions import MSLError
from resources.lib.globals import G
from resources.lib.services.msl.msl_request_builder import MSLRequestBuilder
from resources.lib.services.msl.msl_utils import (generate_logblobs_params, ENDPOINTS,
                                                  MSL_DATA_FILENAME, create_req_params)
from resources.lib.utils.esn import get_esn
from resources.lib.utils.logging import LOG, measure_exec_time_decorator


TCP_KEEP_IDLE = 45
TCP_KEEPALIVE_INTERVAL = 10
TCP_KEEP_CNT = 6


class KeepAliveHTTPAdapter(HTTPAdapter):
    """Transport adapter that allows us to use TCP Keep-Alive."""
    def init_poolmanager(self, connections, maxsize, block=DEFAULT_POOLBLOCK, **pool_kwargs):
        self.poolmanager = KeepAlivePoolManager(num_pools=connections, maxsize=maxsize,
                                                block=block, strict=True, **pool_kwargs)


class KeepAlivePoolManager(PoolManager):
    """
    This Pool Manager has only had the pool_classes_by_scheme variable changed.
    This now points at the TCPKeepAlive connection pools rather than the default connection pools.
    """
    def __init__(self, num_pools=10, headers=None, **connection_pool_kw):
        super().__init__(num_pools=num_pools, headers=headers, **connection_pool_kw)
        self.pool_classes_by_scheme = {
            "http": TCPKeepAliveHTTPConnectionPool,
            "https": TCPKeepAliveHTTPSConnectionPool
        }


class TCPKeepAliveHTTPConnectionPool(HTTPConnectionPool):
    """This class overrides the _validate_conn method in the HTTPConnectionPool class. This is the entry point to use
    for modifying the socket as it is called after the socket is created and before the request is made."""
    def _validate_conn(self, conn):
        """Called right before a request is made, after the socket is created."""
        super()._validate_conn(conn)
        _tcp_keepalive_validation(conn)


class TCPKeepAliveHTTPSConnectionPool(HTTPSConnectionPool):
    """This class overrides the _validate_conn method in the HTTPSConnectionPool class. This is the entry point to use
    for modifying the socket as it is called after the socket is created and before the request is made."""
    def _validate_conn(self, conn):
        """Called right before a request is made, after the socket is created."""
        super()._validate_conn(conn)
        _tcp_keepalive_validation(conn)


# pylint: disable=no-member
def _tcp_keepalive_validation(conn):
    """Set up TCP Keep Alive probes"""
    if sys.platform == 'win32':
        # TCP Keep Alive Probes for Windows
        conn.sock.ioctl(socket.SIO_KEEPALIVE_VALS, (1, TCP_KEEP_IDLE * 1000, TCP_KEEPALIVE_INTERVAL * 1000))
    elif sys.platform == 'linux':
        # TCP Keep Alive Probes for Linux/Android
        # conn.sock could be of WrappedSocket type that not have socket methods (tested on RPI+LibreELEC)
        _setsockopt = getattr(conn.sock, 'setsockopt', conn.sock.socket.setsockopt)
        _setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        if hasattr(socket, 'TCP_KEEPIDLE'):
            _setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, TCP_KEEP_IDLE)
        if hasattr(socket, 'TCP_KEEPINTVL'):
            _setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, TCP_KEEPALIVE_INTERVAL)
        if hasattr(socket, 'TCP_KEEPCNT'):
            _setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, TCP_KEEP_CNT)
    elif sys.platform == 'darwin':
        # TCP Keep Alive Probes for MacOS
        # NOTE: The socket constants from MacOS netinet/tcp.h are not exported by python's socket module
        conn.sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        # The MacOS TCP_KEEPALIVE(0x10) constant should be the same thing of the linux TCP_KEEPIDLE constant
        conn.sock.setsockopt(socket.IPPROTO_TCP, getattr(socket, 'TCP_KEEPIDLE', 0x10), TCP_KEEP_IDLE * 1000)
        conn.sock.setsockopt(socket.IPPROTO_TCP, getattr(socket, 'TCP_KEEPINTVL', 0x101), TCP_KEEPALIVE_INTERVAL * 1000)
        conn.sock.setsockopt(socket.IPPROTO_TCP, getattr(socket, 'TCP_KEEPCNT', 0x102), TCP_KEEP_CNT)


class MSLRequests(MSLRequestBuilder):
    """Provides methods to make MSL requests"""

    def __init__(self, msl_data=None):
        super().__init__()
        from requests import session
        self.session = session()
        self.session.mount('http://', KeepAliveHTTPAdapter())
        self.session.mount('https://', KeepAliveHTTPAdapter())
        self.session.headers.update({
            'User-Agent': common.get_user_agent(),
            'Content-Type': 'text/plain',
            'Accept': '*/*',
            'Host': 'www.netflix.com'
        })
        self._load_msl_data(msl_data)
        self.msl_switch_requested = False

    def _load_msl_data(self, msl_data):
        try:
            self.crypto.load_msl_data(msl_data)
            self.crypto.load_crypto_session(msl_data)
        except Exception:  # pylint: disable=broad-except
            import traceback
            LOG.error(traceback.format_exc())

    def perform_key_handshake(self):
        """Perform a key handshake and initialize crypto keys"""
        esn = get_esn()
        if not esn:
            LOG.error('Cannot perform key handshake, missing ESN')
            return False
        LOG.info('Performing key handshake with ESN: {}', common.censure(esn) if len(esn) > 50 else esn)
        try:
            response = _process_json_response(self._post(ENDPOINTS['manifest'], self.handshake_request(esn)))
            header_data = self.decrypt_header_data(response['headerdata'], False)
            self.crypto.parse_key_response(header_data, esn, True)
        except MSLError as exc:
            if exc.err_number == 207006 and common.get_system_platform() == 'android':
                msg = ('Request failed validation during key exchange\r\n'
                       'To try to solve this problem read the Wiki FAQ on add-on GitHub.')
                raise MSLError(msg) from exc
            raise
        # Delete all the user id tokens (are correlated to the previous mastertoken)
        self.crypto.clear_user_id_tokens()
        LOG.debug('Key handshake successful')
        return True

    def _get_owner_user_id_token(self):
        """A way to get the user token id of owner profile"""
        # In order to get a user id token of another (non-owner) profile you must make a request with SWITCH_PROFILE
        # authentication scheme (a custom authentication for netflix), and this request can be directly included
        # in the MSL manifest request.
        # But in order to execute this switch profile, you need to have the user id token of the main (owner) profile.
        # The only way (found to now) to get it immediately, is send a logblob event request, and save the
        # user id token obtained in the response.
        LOG.debug('Requesting logblog')
        endpoint_url = ENDPOINTS['logblobs'] + create_req_params(0, 'bind')
        response = self.chunked_request(endpoint_url,
                                        self.build_request_data('/logblob', generate_logblobs_params()),
                                        get_esn(),
                                        force_auth_credential=True)
        LOG.debug('Response of logblob request: {}', response)

    def _mastertoken_checks(self):
        """Perform checks to the MasterToken and executes a new key handshake when necessary"""
        is_handshake_required = False
        if self.crypto.mastertoken:
            if self.crypto.is_current_mastertoken_expired():
                LOG.debug('Stored MSL MasterToken is expired, a new key handshake will be performed')
                is_handshake_required = True
            else:
                # Check if the current ESN is same of ESN bound to MasterToken
                if get_esn() != self.crypto.bound_esn:
                    LOG.debug('Stored MSL MasterToken is bound to a different ESN, '
                              'a new key handshake will be performed')
                    is_handshake_required = True
        else:
            LOG.debug('MSL MasterToken is not available, a new key handshake will be performed')
            is_handshake_required = True
        if is_handshake_required:
            if self.perform_key_handshake():
                msl_data = json.loads(common.load_file_def(MSL_DATA_FILENAME))
                self.crypto.load_msl_data(msl_data)
                self.crypto.load_crypto_session(msl_data)

    def _check_user_id_token(self, disable_msl_switch, force_auth_credential=False):
        """
        Performs user id token checks and return the auth data
        checks: uid token validity, get if needed the owner uid token, set when use the switch

        :param: disable_msl_switch: to be used in requests that cannot make the switch
        :param: force_auth_credential: force the use of authentication with credentials
        :return: auth data that will be used in MSLRequestBuilder _add_auth_info
        """
        # Warning: the user id token contains also contains the identity of the netflix profile
        # therefore it is necessary to use the right user id token for the request
        current_profile_guid = G.LOCAL_DB.get_active_profile_guid()
        owner_profile_guid = G.LOCAL_DB.get_guid_owner_profile()
        use_switch_profile = False
        user_id_token = None

        if not force_auth_credential:
            if current_profile_guid == owner_profile_guid:
                # The request will be executed from the owner profile
                # By default MSL is associated to the owner profile, then is not necessary get the owner token id
                # and it is not necessary use the MSL profile switch
                user_id_token = self.crypto.get_user_id_token(current_profile_guid)
                # The user_id_token can return None when the add-on is installed from scratch,
                # in this case will be used the authentication with the user credentials
            else:
                # The request will be executed from a non-owner profile
                # Get the non-owner profile token id, by checking that exists and it is valid
                user_id_token = self.crypto.get_user_id_token(current_profile_guid)
                if not user_id_token and not disable_msl_switch:
                    # The token does not exist/valid, you must set the MSL profile switch
                    use_switch_profile = True
                    # First check if the owner profile token exist and it is valid
                    user_id_token = self.crypto.get_user_id_token(owner_profile_guid)
                    if not user_id_token:
                        # The owner profile token id does not exist/valid, then get it
                        self._get_owner_user_id_token()
                        user_id_token = self.crypto.get_user_id_token(owner_profile_guid)
                    # Mark msl_switch_requested as True in order to make a bind event request
                    self.msl_switch_requested = True
        return {'use_switch_profile': use_switch_profile, 'user_id_token': user_id_token}

    @measure_exec_time_decorator(is_immediate=True)
    def chunked_request(self, endpoint, request_data, esn, disable_msl_switch=True, force_auth_credential=False):
        """Do a POST request and process the chunked response"""
        self._mastertoken_checks()
        auth_data = self._check_user_id_token(disable_msl_switch, force_auth_credential)
        LOG.debug('Chunked request will be executed with auth data: {}', auth_data)

        chunked_response = self._process_chunked_response(
            self._post(endpoint, self.msl_request(request_data, esn, auth_data)),
            save_uid_token_to_owner=auth_data['user_id_token'] is None)
        return chunked_response['result']

    def _post(self, endpoint, request_data):
        """Execute a post request"""
        is_attempts_enabled = 'reqAttempt=' in endpoint
        retry = 1
        while True:
            try:
                if is_attempts_enabled:
                    _endpoint = endpoint.replace('reqAttempt=', 'reqAttempt=' + str(retry))
                else:
                    _endpoint = endpoint
                LOG.debug('Executing POST request to {}', _endpoint)
                start = time.perf_counter()
                response = self.session.post(_endpoint, request_data, timeout=4)
                LOG.debug('Request took {}s', time.perf_counter() - start)
                LOG.debug('Request returned response with status {}', response.status_code)
                break
            except req_exceptions.ConnectionError as exc:
                LOG.error('HTTP request error: {}', exc)
                if retry == 3:
                    raise
                retry += 1
                LOG.warn('Another attempt will be performed ({})', retry)
        response.raise_for_status()
        return response.text

    @measure_exec_time_decorator(is_immediate=True)
    def _process_chunked_response(self, response, save_uid_token_to_owner=False):
        """Parse and decrypt an encrypted chunked response. Raise an error if the response is plaintext json"""
        LOG.debug('Received encrypted chunked response')
        if not response:
            return {}
        response = _parse_chunks(response)
        # TODO: sending for the renewal request is not yet implemented
        # if self.crypto.get_current_mastertoken_validity()['is_renewable']:
        #     # Check if mastertoken is renewed
        #     self.request_builder.crypto.compare_mastertoken(response['header']['mastertoken'])

        header_data = self.decrypt_header_data(response['header'].get('headerdata'))

        if 'useridtoken' in header_data:
            # Save the user id token for the future msl requests
            profile_guid = G.LOCAL_DB.get_guid_owner_profile() if save_uid_token_to_owner else\
                G.LOCAL_DB.get_active_profile_guid()
            self.crypto.save_user_id_token(profile_guid, header_data['useridtoken'])
        # if 'keyresponsedata' in header_data:
        #     LOG.debug('Found key handshake in response data')
        #     # Update current mastertoken
        #     self.request_builder.crypto.parse_key_response(header_data, True)
        decrypted_response = _decrypt_chunks(response['payloads'], self.crypto)
        return _raise_if_error(decrypted_response)


@measure_exec_time_decorator(is_immediate=True)
def _process_json_response(response):
    """Execute a post request and expect a JSON response"""
    try:
        return _raise_if_error(json.loads(response))
    except ValueError as exc:
        raise MSLError('Expected JSON format type, got {}'.format(response)) from exc


def _raise_if_error(decoded_response):
    raise_error = False
    # Catch a manifest/chunk error
    if any(key in decoded_response for key in ['error', 'errordata']):
        raise_error = True
    # Catch a license error
    if 'result' in decoded_response and isinstance(decoded_response.get('result'), list):
        if 'error' in decoded_response['result'][0]:
            raise_error = True
    if raise_error:
        LOG.error('Full MSL error information:')
        LOG.error(json.dumps(decoded_response))
        err_message, err_number = _get_error_details(decoded_response)
        raise MSLError(err_message, err_number)
    return decoded_response


def _get_error_details(decoded_response):
    err_message = 'Unhandled error check log.'
    err_number = None
    # Catch a chunk error
    if 'errordata' in decoded_response:
        err_data = json.loads(base64.standard_b64decode(decoded_response['errordata']))
        err_message = err_data['errormsg']
        err_number = err_data['internalcode']
    # Catch a manifest error
    elif 'error' in decoded_response:
        if decoded_response['error'].get('errorDisplayMessage'):
            err_message = decoded_response['error']['errorDisplayMessage']
            err_number = decoded_response['error'].get('bladeRunnerCode')
    # Catch a license error
    elif 'result' in decoded_response and isinstance(decoded_response.get('result'), list):
        if 'error' in decoded_response['result'][0]:
            if decoded_response['result'][0]['error'].get('errorDisplayMessage'):
                err_message = decoded_response['result'][0]['error']['errorDisplayMessage']
                err_number = decoded_response['result'][0]['error'].get('bladeRunnerCode')
    return err_message, err_number


@measure_exec_time_decorator(is_immediate=True)
def _parse_chunks(message):
    try:
        msg_parts = json.loads('[' + message.replace('}{', '},{') + ']')
        header = None
        payloads = []
        for msg_part in msg_parts:
            if 'headerdata' in msg_part:
                header = msg_part
            elif 'payload' in msg_part:
                payloads.append(msg_part)
        return {'header': header, 'payloads': payloads}
    except Exception as exc:  # pylint: disable=broad-except
        LOG.error('Unable to parse the chunks due to error: {}', exc)
        LOG.debug('Message data: {}', message)
        raise


@measure_exec_time_decorator(is_immediate=True)
def _decrypt_chunks(chunks, crypto):
    decrypted_payload = ''
    for chunk in chunks:
        payload = chunk.get('payload')
        decoded_payload = base64.standard_b64decode(payload)
        encryption_envelope = json.loads(decoded_payload)
        # Decrypt the text
        plaintext = crypto.decrypt(
            base64.standard_b64decode(encryption_envelope['iv']),
            base64.standard_b64decode(encryption_envelope.get('ciphertext')))
        # unpad the plaintext
        plaintext = json.loads(plaintext)
        data = plaintext.get('data')

        # uncompress data if compressed
        if plaintext.get('compressionalgo') == 'GZIP':
            decoded_data = base64.standard_b64decode(data)
            data = zlib.decompress(decoded_data, 16 + zlib.MAX_WBITS).decode('utf-8')
        else:
            data = base64.standard_b64decode(data).decode('utf-8')

        decrypted_payload += data
    return json.loads(decrypted_payload)
