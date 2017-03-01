#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: jiawei@shoplex.com
# Created at 2017-01-22

from __future__ import absolute_import, division, print_function, \
    with_statement

import socket
import logging
import random
import hashlib

from flask import Flask, abort, request, jsonify
from flask_inputs import Inputs
from flask_inputs.validators import JsonSchema

logger = logging.getLogger('Manager API')


class FlaskDeployedViaTornado(Flask):
    @property
    def logger(self):
        return logger

    def run(self, host=None, port=None, debug=None, **options):
        import tornado.wsgi
        import tornado.ioloop
        import tornado.httpserver
        import tornado.web

        if host is None:
            host = '0.0.0.0'
        if port is None:
            port = 5000
        if debug is not None:
            self.debug = bool(debug)
            self.logger.setLevel(logging.DEBUG)

        hostname = host
        port = port
        application = self
        use_reloader = self.debug
        use_debugger = self.debug

        if use_debugger:
            from werkzeug.debug import DebuggedApplication
            application = DebuggedApplication(application, True)

        container = tornado.wsgi.WSGIContainer(application)
        self.http_server = tornado.httpserver.HTTPServer(container)
        self.http_server.listen(port, hostname)
        if use_reloader:
            from tornado import autoreload
            autoreload.start()

        self.logger.info('Manager API running on %s:%s', hostname, port)
        self.ioloop = tornado.ioloop.IOLoop.current()
        self.ioloop.start()


class RemovePortInputs(Inputs):
    json = [
        JsonSchema(schema={
            'type': 'object',
            'properties': {
                'port': {
                    'type': [
                        'string',
                        'number',
                    ],
                }
            }
        })
    ]


def pick_unused_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('localhost', 0))
    addr, port = s.getsockname()
    s.close()
    return port


app = FlaskDeployedViaTornado(__name__)


@app.before_request
def authenticate():
    if not request.headers.get('Authorization') \
            == app.config.get('AUTHORIZATION_KEY'):
        abort(403)


@app.route('/add-port', methods=['POST'])
def add_port():
    app.logger.debug('Receive request to add port')

    cli = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    manager_host, manager_port = app.config.get('MANAGER_ADDRESS').split(':')
    cli.connect((manager_host, int(manager_port)))

    port = pick_unused_port()
    password = hashlib.md5(
        bytes(random.randint(1, 100) * random.randint(1, 200))).hexdigest()

    cli.send(b'add: {"server_port":' + bytes(port) +
             b', "password":"' + bytes(password) + b'"}')

    cli.close()

    data = {
        'port': port,
        'password': password,
    }

    return jsonify(message='success', data=data)


@app.route('/remove-port', methods=['POST'])
def remove_port():
    app.logger.debug('Receive request to add port')

    inputs = RemovePortInputs(request)
    if not inputs.validate():
        return jsonify(message='Got bad request', errors=inputs.errors)

    port = int(request.json.get('port'))

    cli = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    manager_host, manager_port = app.config.get('MANAGER_ADDRESS').split(':')
    cli.connect((manager_host, int(manager_port)))

    cli.send('remove: {"server_port": ' + bytes(port) + '}')
    cli.close()

    return jsonify(message='success')
