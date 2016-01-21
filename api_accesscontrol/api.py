#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Andy Sayler
# Copyright 2015


### Imports ###

import functools
import uuid
import datetime

import flask
import flask.ext.httpauth
import flask.ext.cors

from pcollections import drivers
from pcollections import backends

from pytutamen_server import datatypes
from pytutamen_server import accesscontrol

from . import exceptions
from . import config


### Constants ###

DUR_ONE_MINUTE = datetime.timedelta(minutes=1)
DUR_ONE_HOUR = datetime.timedelta(hours=1)
DUR_ONE_DAY = datetime.timedelta(days=1)
DUR_ONE_MONTH = datetime.timedelta(days=28)
DUR_ONE_YEAR = datetime.timedelta(days=366)
DUR_TEN_YEAR = datetime.timedelta(days=3660)

_EP_PUBLIC = "public"
_EP_BOOTSTRAP = "bootstrap"

_KEY_CACERT = "cacert"
_KEY_SIGKEY = "sigkey"

_KEY_ACCOUNTS = "accounts"
_KEY_CLIENTS = "clients"
_KEY_CLIENTS_CERTS = "{}_certs".format(_KEY_CLIENTS)

_KEY_AUTHORIZATIONS = "authorizations"


### Global Setup ###

app = flask.Flask(__name__)
app.config['JSON_AS_ASCII'] = False
app.debug = False
cors = flask.ext.cors.CORS(app, headers=["Content-Type", "Authorization"])


### Logging ###

if not app.testing:

    import logging
    import logging.handlers

    loggers = [app.logger, logging.getLogger('pytutamen_server')]

    formatter_line = logging.Formatter('%(levelname)s: %(module)s - %(message)s')
    formatter_line_time = logging.Formatter('%(asctime)s %(levelname)s: %(module)s - %(message)s')

    # Stream Handler
    handler_stream = logging.StreamHandler()
    handler_stream.setFormatter(formatter_line)
    handler_stream.setLevel(logging.DEBUG)

    # File Handler
    # if not os.path.exists(_LOGGING_PATH):
    #     os.makedirs(_LOGGING_PATH)
    # logfile_path = "{:s}/{:s}".format(_LOGGING_PATH, "api.log")
    # handler_file = logging.handlers.WatchedFileHandler(logfile_path)
    # handler_file.setFormatter(formatter_line_time)
    # if app.debug:
    #     handler_file.setLevel(logging.DEBUG)
    # else:
    #     handler_file.setLevel(logging.INFO)

    for logger in loggers:
        logger.setLevel(logging.DEBUG)
        logger.addHandler(handler_stream)
    #    logger.addHandler(handler_file)


### Setup/Teardown ###

@app.before_request
def before_request():

    flask.g.pdriver = drivers.RedisDriver(db=config.REDIS_DB)
    flask.g.pbackend = backends.RedisAtomicBackend(flask.g.pdriver)
    flask.g.srv_ac = accesscontrol.AccessControlServer(flask.g.pbackend, create=False)

@app.teardown_request
def teardown_request(exception):
    pass


### Auth Decorators ###

def authenticate_client():

    def _decorator(func):

        @functools.wraps(func)
        def _wrapper(*args, **kwargs):

            cert_info = flask.request.environ
            status = cert_info['SSL_CLIENT_VERIFY']
            if status != 'SUCCESS':
                msg = "Could not verify client cert: {}".format(status)
                app.logger.warning(msg)
                raise exceptions.SSLClientCertError(msg)

            accountuid = cert_info['SSL_CLIENT_S_DN_O']
            clientuid = uuid.UUID(cert_info['SSL_CLIENT_S_DN_CN'])
            msg = "Authenticated Client '{}' for Account '{}'".format(clientuid, accountuid)
            app.logger.debug(msg)
            flask.g.accountuid = accountuid
            flask.g.clientuid = clientuid

            # Call Function
            return func(*args, **kwargs)

        return _wrapper

    return _decorator


### Endpoints ###

## Root Endpoints ##

@app.route("/", methods=['GET'])
def get_root():

    app.logger.debug("GET ROOT")
    return app.send_static_file('index.html')


## Public Endpoints ##

@app.route("/{}/{}/".format(_EP_PUBLIC, _KEY_CACERT), methods=['GET'])
def get_pub_cacert():

    app.logger.debug("GET PUB CACERT")
    json_out = {_KEY_CACERT: flask.g.srv_ac.ca_crt}
    return flask.jsonify(json_out)

@app.route("/{}/{}/".format(_EP_PUBLIC, _KEY_SIGKEY), methods=['GET'])
def get_pub_sigkey():

    app.logger.debug("GET PUB SIGKEY")
    json_out = {_KEY_SIGKEY: flask.g.srv_ac.sigkey_pub}
    return flask.jsonify(json_out)


## Bootstrap Endpoints ##

@app.route("/{}/{}/".format(_EP_BOOTSTRAP, _KEY_ACCOUNTS), methods=['POST'])
def bootstrap_account_create():

    app.logger.debug("BOOTSTRAP ACCOUNT")

    json_in = flask.request.get_json(force=True)
    app.logger.debug("json_in = '{}'".format(json_in))

    if config.BOOTSTRAP_PASSWORD:
        password = json_in.get('password', "")
        if password != config.BOOTSTRAP_PASSWORD:
            flask.abort(401)

    account_userdata = json_in.get('account_userdata', {})
    app.logger.debug("account_userdata = '{}'".format(account_userdata))
    account_uid = json_in.get('account_uid', None)
    app.logger.debug("accuid = '{}'".format(account_uid))

    client_userdata = json_in.get('client_userdata', {})
    app.logger.debug("client_userdata = '{}'".format(client_userdata))
    client_uid = json_in.get('client_uid', None)
    app.logger.debug("client_uid = '{}'".format(client_uid))
    client_csr = json_in['client_csr']
    app.logger.debug("client_csr = '{}'".format(client_csr))

    account = flask.g.srv_ac.accounts.create(userdata=account_userdata,
                                             key=account_uid)
    app.logger.debug("account = '{}'".format(account))

    client = account.clients.create(userdata=client_userdata,
                                    key=client_uid,
                                    csr_pem=client_csr)
    app.logger.debug("client = '{}'".format(client))

    json_out = {_KEY_ACCOUNTS: [account.key],
                _KEY_CLIENTS: [client.key],
                _KEY_CLIENTS_CERTS: {client.key: client.crt}}
    return flask.jsonify(json_out)


## Authorization Endpoints ##

@app.route("/{}/".format(_KEY_AUTHORIZATIONS), methods=['POST'])
@authenticate_client()
def create_authorizations():

    app.logger.debug("POST AUTHORIZATIONS")

    json_in = flask.request.get_json(force=True)
    app.logger.debug("json_in = '{}'".format(json_in))

    userdata = json_in.get('userdata', {})
    app.logger.debug("userdata = '{}'".format(userdata))

    objperm = json_in['objperm']
    app.logger.debug("objperm = '{}'".format(objperm))
    objtype = json_in['objtype']
    app.logger.debug("objtype = '{}'".format(objtype))
    objuid = json_in.get('objuid', None)
    objuid = uuid.UUID(objuid) if objuid else None
    app.logger.debug("objuid = '{}'".format(objuid))

    expiration = datetime.datetime.utcnow() + DUR_ONE_HOUR

    authz = flask.g.srv_ac.authorizations.create(userdata=userdata,
                                                 clientuid=flask.g.clientuid,
                                                 expiration=expiration,
                                                 objperm=objperm,
                                                 objtype=objtype,
                                                 objuid=objuid)
    app.logger.debug("authz = '{}'".format(authz))

    # Todo: make this asynchronous via seperate verification daemon
    authz.verify()

    json_out = {_KEY_AUTHORIZATIONS: [authz.key]}
    return flask.jsonify(json_out)

@app.route("/{}/<authz_uid>/".format(_KEY_AUTHORIZATIONS), methods=['GET'])
@authenticate_client()
def get_authorizations(authz_uid):

    app.logger.debug("GET AUTHORIZATIONS")
    authz = flask.g.srv_ac.authorizations.get(key=authz_uid)
    app.logger.debug("authz = '{}'".format(authz))

    # Todo: verify request came from same client

    json_out = {'status': authz.status,
                'expiration': authz.expiration_timestamp,
                'objperm': authz.objperm,
                'objtype': authz.objtype,
                'objuid': str(authz.objuid)}

    if authz.status == accesscontrol.AUTHZ_STATUS_APPROVED:
        json_out['token'] = authz.export_token()
    else:
        json_out['token'] = ""

    return flask.jsonify(json_out)


### Error Handling ###

@app.errorhandler(datatypes.ObjectExists)
def object_exists(error):
    err = { 'status': 409,
            'message': "{}".format(error) }
    app.logger.info("Client Error: ObjectExists: {}".format(err))
    res = flask.jsonify(err)
    res.status_code = err['status']
    return res

@app.errorhandler(datatypes.ObjectDNE)
def object_exists(error):
    err = { 'status': 404,
            'message': "{}".format(error) }
    app.logger.info("Client Error: Object Does Not Exist: {}".format(err))
    res = flask.jsonify(err)
    res.status_code = err['status']
    return res

# @app.errorhandler(KeyError)
# def bad_key(error):
#     err = { 'status': 400,
#             'message': "{}".format(error) }
#     app.logger.info("Client Error: KeyError: {}".format(err))
#     res = flask.jsonify(err)
#     res.status_code = err['status']
#     return res

# @app.errorhandler(ValueError)
# def bad_value(error):
#     err = { 'status': 400,
#             'message': "{}".format(error) }
#     app.logger.info("Client Error: ValueError: {}".format(err))
#     res = flask.jsonify(err)
#     res.status_code = err['status']
#     return res

# @app.errorhandler(TypeError)
# def bad_type(error):
#     err = { 'status': 400,
#             'message': "{}".format(error) }
#     app.logger.info("Client Error: TypeError: {}".format(err))
#     res = flask.jsonify(err)
#     res.status_code = err['status']
#     return res

@app.errorhandler(exceptions.SSLClientCertError)
def bad_cert(error):
    err = { 'status': 401,
            'message': "{}".format(error) }
    app.logger.info("Client Error: SSLClientCertError: {}".format(err))
    res = flask.jsonify(err)
    res.status_code = err['status']
    return res

@app.errorhandler(400)
def bad_request(error=False):
    err = { 'status': 400,
            'message': "Malformed request" }
    app.logger.info("Client Error: 400: {}".format(err))
    res = flask.jsonify(err)
    res.status_code = err['status']
    return res

@app.errorhandler(401)
def not_authorized(error=False):
    err = { 'status': 401,
            'message': "Not Authorized" }
    app.logger.info("Client Error: 401: {}".format(err))
    res = flask.jsonify(err)
    res.status_code = err['status']
    return res

@app.errorhandler(404)
def not_found(error=False):
    err = { 'status': 404,
            'message': "Not Found: {}".format(flask.request.url) }
    app.logger.info("Client Error: 404: {}".format(err))
    res = flask.jsonify(err)
    res.status_code = err['status']
    return res

@app.errorhandler(405)
def bad_method(error=False):
    err = { 'status': 405,
            'message': "Bad Method: {} {}".format(flask.request.method, flask.request.url) }
    app.logger.info("Client Error: 405: {}".format(err))
    res = flask.jsonify(err)
    res.status_code = err['status']
    return res


### Run Test Server ###

if __name__ == "__main__":
    app.run(debug=True)
