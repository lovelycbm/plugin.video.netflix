# -*- coding: utf-8 -*-
"""
    Copyright (C) 2017 Sebastian Golasch (plugin.video.netflix)
    Copyright (C) 2018 Caphm (original implementation module)
    Copyright (C) 2019 Stefano Gottardo - @CastagnaIT
    Initialize the netflix session

    SPDX-License-Identifier: MIT
    See LICENSES/MIT.md for more information.
"""
from __future__ import absolute_import, division, unicode_literals

import socket
import sys

from requests.adapters import HTTPAdapter, DEFAULT_POOLBLOCK
from urllib3 import PoolManager, HTTPSConnectionPool, HTTPConnectionPool


import resources.lib.common as common
from resources.lib.database.db_utils import TABLE_SESSION
from resources.lib.globals import G
from resources.lib.utils.logging import LOG


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
        PoolManager.__init__(self, num_pools=num_pools, headers=headers, **connection_pool_kw)
        self.pool_classes_by_scheme = {
            "http": TCPKeepAliveHTTPConnectionPool,
            "https": TCPKeepAliveHTTPSConnectionPool
        }


class TCPKeepAliveHTTPConnectionPool(HTTPConnectionPool):
    """This class overrides the _validate_conn method in the HTTPConnectionPool class. This is the entry point to use
    for modifying the socket as it is called after the socket is created and before the request is made."""
    def _validate_conn(self, conn):
        """Called right before a request is made, after the socket is created."""
        HTTPConnectionPool._validate_conn(self, conn)
        _tcp_keepalive_validation(conn)


class TCPKeepAliveHTTPSConnectionPool(HTTPSConnectionPool):
    """This class overrides the _validate_conn method in the HTTPSConnectionPool class. This is the entry point to use
    for modifying the socket as it is called after the socket is created and before the request is made."""
    def _validate_conn(self, conn):
        """Called right before a request is made, after the socket is created."""
        HTTPSConnectionPool._validate_conn(self, conn)
        _tcp_keepalive_validation(conn)


def _tcp_keepalive_validation(conn):
    """Set up TCP Keep Alive probes"""
    if sys.platform == 'win32':
        # TCP Keep Alive Probes for Windows
        conn.sock.ioctl(socket.SIO_KEEPALIVE_VALS, (1, TCP_KEEP_IDLE * 1000, TCP_KEEPALIVE_INTERVAL * 1000))
    elif sys.platform.startswith('linux'):
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
        if hasattr(socket, 'TCP_KEEPIDLE'):
            conn.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, TCP_KEEP_IDLE * 1000)
        else:
            # The MacOS TCP_KEEPALIVE(0x10) constant should be the same thing of the linux TCP_KEEPIDLE constant
            conn.sock.setsockopt(socket.IPPROTO_TCP, 0x10, TCP_KEEP_IDLE * 1000)
        if hasattr(socket, 'TCP_KEEPINTVL'):
            conn.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, TCP_KEEPALIVE_INTERVAL * 1000)
        else:
            conn.sock.setsockopt(socket.IPPROTO_TCP, 0x101, TCP_KEEPALIVE_INTERVAL * 1000)
        if hasattr(socket, 'TCP_KEEPCNT'):
            conn.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, TCP_KEEP_CNT)
        else:
            conn.sock.setsockopt(socket.IPPROTO_TCP, 0x102, TCP_KEEP_CNT)


class SessionBase(object):
    """Initialize the netflix session"""

    session = None
    """The requests.session object to handle communication to Netflix"""

    verify_ssl = True
    """Use SSL verification when performing requests"""

    # Functions from derived classes to allow perform particular operations in parent classes
    external_func_activate_profile = None  # (set by nfsession_op.py)

    def __init__(self):
        self.verify_ssl = bool(G.ADDON.getSettingBool('ssl_verification'))
        self._init_session()

    def _init_session(self):
        """Initialize the session to use for all future connections"""
        try:
            self.session.close()
            LOG.info('Session closed')
        except AttributeError:
            pass
        from requests import session
        self.session = session()
        self.session.mount('http://', KeepAliveHTTPAdapter())
        self.session.mount('https://', KeepAliveHTTPAdapter())
        self.session.max_redirects = 10  # Too much redirects should means some problem
        self.session.headers.update({
            'User-Agent': common.get_user_agent(enable_android_mediaflag_fix=True),
            'Accept-Encoding': 'gzip, deflate, br',
            'Host': 'www.netflix.com'
        })
        LOG.info('Initialized new session')

    @property
    def auth_url(self):
        """Access rights to make HTTP requests on an endpoint"""
        return G.LOCAL_DB.get_value('auth_url', table=TABLE_SESSION)

    @auth_url.setter
    def auth_url(self, value):
        G.LOCAL_DB.set_value('auth_url', value, TABLE_SESSION)
