#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Andy Sayler
# Copyright 2015, 2016


### Imports ###

import functools
import uuid
from datetime import datetime

import flask
import flask.ext.cors

from pcollections import drivers
from pcollections import backends

from pytutamen_server import constants
from pytutamen_server import utility
from pytutamen_server import datatypes
from pytutamen_server import accesscontrol

from . import exceptions
from . import config


### Constants ###

_TOKENS_HEADER = 'tutamen-tokens'
_TOKENS_DELIMINATOR = ':'

_EP_PUBLIC = "public"
_EP_BOOTSTRAP = "bootstrap"
_EP_TWILIO = "twilio"

_KEY_CACERT = "cacert"
_KEY_SIGKEY = "sigkey"

_KEY_ACCOUNTS = "accounts"
_KEY_CLIENTS = "clients"
_KEY_CLIENTS_CERTS = "{}_certs".format(_KEY_CLIENTS)

_KEY_AUTHORIZATIONS = "authorizations"
_KEY_AUTHENTICATORS = "authenticators"
_KEY_VERIFIERS = "verifiers"
_KEY_PERMISSIONS = "permissions"

_DEFAULT_TOKEN_DURATION = config.TOKENS_MINUTES * constants.DUR_ONE_MINUTE


### Global Setup ###

app = flask.Flask(__name__)
app.config['JSON_AS_ASCII'] = False
app.debug = False
cors = flask.ext.cors.CORS(app, headers=["Content-Type", "Authorization"])


### Logging ###

if not app.testing:

    import logging
    import logging.handlers

    loggers = [app.logger, logging.getLogger('pytutamen_server'), logging.getLogger('authmods')]

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

            env = flask.request.environ
            status = env.get('SSL_CLIENT_VERIFY', None)
            if status != 'SUCCESS':
                msg = "Could not verify client cert: {}".format(status)
                app.logger.warning(msg)
                raise exceptions.SSLClientCertError(msg)

            accountuid = env.get('SSL_CLIENT_S_DN_OU', None)
            clientuid = env.get('SSL_CLIENT_S_DN_CN', None)
            try:
                accountuid = uuid.UUID(accountuid) if accountuid else None
                clientuid = uuid.UUID(clientuid) if clientuid else None
            except ValueError as err:
                msg = "Client cert contains bad uuid: {}".format(err)
                app.logger.warning(msg)
                raise exceptions.SSLClientCertError(msg) from err
            msg = "Authenticated Client '{}' from Account '{}'".format(clientuid, accountuid)
            app.logger.debug(msg)
            flask.g.accountuid = accountuid
            flask.g.clientuid = clientuid

            # Call Function
            return func(*args, **kwargs)

        return _wrapper

    return _decorator

def get_token():

    def _decorator(func):

        @functools.wraps(func)
        def _wrapper(*args, **kwargs):

            header = flask.request.headers.get(_TOKENS_HEADER, "")

            if not header:
                msg = "Client sent blank or missing token header"
                app.logger.warning(msg)
                raise exceptions.TokensError(msg)

            tokens = header.split(_TOKENS_DELIMINATOR)
            app.logger.debug("tokens = {}".format(tokens))

            if not tokens:
                msg = "Client sent no parsable tokens"
                app.logger.warning(msg)
                raise exceptions.TokensError(msg)

            if len(tokens) > 1:
                msg = "Client sent too many tokens"
                app.logger.warning(msg)
                raise exceptions.TokensError(msg)

            flask.g.token = tokens[0]

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


## Twilio Endpoints ##

@app.route("/{}/".format(_EP_TWILIO), methods=['POST'])
def post_twilio():

    app.logger.debug("POST TWILIO")
    msgdata = flask.request.values
    app.logger.debug("msgdata = {}".format(msgdata))
    xml_out = '<?xml version="1.0" encoding="UTF-8"?><Response></Response>'
    return flask.Response(xml_out, mimetype='text/xml')


## Bootstrap Endpoints ##

@app.route("/{}/{}/".format(_EP_BOOTSTRAP, _KEY_ACCOUNTS), methods=['POST'])
def bootstrap_account_create():

    app.logger.debug("BOOTSTRAP ACCOUNT")

    # Log JSON
    json_in = flask.request.get_json(force=True)
    app.logger.debug("json_in = '{}'".format(json_in))

    # Check Password
    if config.BOOTSTRAP_PASSWORD:
        password = json_in.get('password', "")
        if password != config.BOOTSTRAP_PASSWORD:
            flask.abort(401)

    # Get Required Attributes
    try:
        client_csr = json_in['client_csr']
    except KeyError as err:
        msg = "Missing required parameter: {}".format(err)
        app.logger.warning(msg)
        raise exceptions.MissingAttributeError(msg) from err

    # Get Optional Attributes
    account_userdata = json_in.get('account_userdata', {})
    account_uid = json_in.get('account_uid', None)
    client_userdata = json_in.get('client_userdata', {})
    client_uid = json_in.get('client_uid', None)

    # Log Attributes
    app.logger.debug("client_csr = '{}'".format(client_csr))
    app.logger.debug("account_userdata = '{}'".format(account_userdata))
    app.logger.debug("accuid = '{}'".format(account_uid))
    app.logger.debug("client_userdata = '{}'".format(client_userdata))
    app.logger.debug("client_uid = '{}'".format(client_uid))

    # Create Account
    account = flask.g.srv_ac.accounts.create(userdata=account_userdata,
                                             key=account_uid)
    app.logger.debug("account = '{}'".format(account))

    # Create Client
    client = account.clients.create(userdata=client_userdata,
                                    key=client_uid,
                                    csr_pem=client_csr)
    app.logger.debug("client = '{}'".format(client))

    # Returen Response
    json_out = {_KEY_ACCOUNTS: [account.key],
                _KEY_CLIENTS: [client.key],
                _KEY_CLIENTS_CERTS: {client.key: client.crt}}
    app.logger.debug("json_out = '{}'".format(json_out))
    return flask.jsonify(json_out)


## Authorization Endpoints ##

@app.route("/{}/".format(_KEY_AUTHORIZATIONS), methods=['POST'])
@authenticate_client()
def create_authorizations():

    app.logger.debug("POST AUTHORIZATIONS")

    # Log JSON
    json_in = flask.request.get_json(force=True)
    app.logger.debug("json_in = '{}'".format(json_in))

    # Get Required Attributes
    try:
        objperm = json_in['objperm']
        objtype = json_in['objtype']
    except KeyError as err:
        msg = "Missing required parameter: {}".format(err)
        app.logger.warning(msg)
        raise exceptions.MissingAttributeError(msg) from err

    # Get Optional Attributes
    userdata = json_in.get('userdata', {})
    objuid = json_in.get('objuid', None)
    objuid = uuid.UUID(objuid) if objuid else None
    expiration = json_in.get('expiration', None)
    expiration = int(expiration) if expiration else None
    if expiration:
        expiration = datetime.fromtimestamp(expiration)
    else:
        expiration = datetime.utcnow() + _DEFAULT_TOKEN_DURATION

    # Log Attributes
    app.logger.debug("objperm = '{}'".format(objperm))
    app.logger.debug("objtype = '{}'".format(objtype))
    app.logger.debug("objuid = '{}'".format(objuid))
    app.logger.debug("userdata = '{}'".format(userdata))
    app.logger.debug("expiration = '{}'".format(expiration))

    # Create Object
    authz = flask.g.srv_ac.authorizations.create(userdata=userdata,
                                                 accountuid=flask.g.accountuid,
                                                 clientuid=flask.g.clientuid,
                                                 expiration=expiration,
                                                 objperm=objperm,
                                                 objtype=objtype,
                                                 objuid=objuid)
    app.logger.debug("authz = '{}'".format(authz))

    # Todo: make this asynchronous via seperate verification daemon
    authz.verify()

    # Return Response
    json_out = {_KEY_AUTHORIZATIONS: [authz.key]}
    app.logger.debug("json_out = '{}'".format(json_out))
    return flask.jsonify(json_out)

@app.route("/{}/<authz_uid>/".format(_KEY_AUTHORIZATIONS), methods=['GET'])
@authenticate_client()
def get_authorizations(authz_uid):

    app.logger.debug("GET AUTHORIZATIONS")

    # Get Athorization
    authz = flask.g.srv_ac.authorizations.get(key=authz_uid)
    app.logger.debug("authz = '{}'".format(authz))

    # Verify Matching Account
    if (flask.g.accountuid != authz.accountuid):
        msg = "Certificate accountuid '{}' does not".format(flask.g.accountuid)
        msg += " match authorization accountuid '{}'".format(authz.accountuid)
        app.logger.warning(msg)
        raise exceptions.AccountUIDError(msg)

    # Verify Matching Client
    if (flask.g.clientuid != authz.clientuid):
        msg = "Certificate clientuid '{}' does not".format(flask.g.clientuid)
        msg += " match authorization clientuid '{}'".format(authz.clientuid)
        app.logger.warning(msg)
        raise exceptions.ClientUIDError(msg)

    # Build Output JSON
    json_out = {'status': authz.status,
                'expiration': authz.expiration_timestamp,
                'objperm': authz.objperm,
                'objtype': authz.objtype,
                'objuid': str(authz.objuid)}

    # Fetch token if ready
    if authz.status == constants.AUTHZ_STATUS_APPROVED:
        json_out['token'] = authz.export_token()
    else:
        json_out['token'] = ""

    # Return Response
    log_out = dict(json_out)
    log_out['token'] = "REDACTED" if log_out['token'] else log_out['token']
    app.logger.debug("json_out = '{}'".format(log_out))
    return flask.jsonify(json_out)


## Authenticator Endpoints ##

@app.route("/{}/".format(_KEY_AUTHENTICATORS), methods=['POST'])
@authenticate_client()
@get_token()
def create_authenticators():

    app.logger.debug("POST AUTHENTICATORS")

    # Verify Tokens
    objperm = constants.PERM_CREATE
    objtype = constants.TYPE_SRV_AC
    utility.verify_auth_token_sigkey(flask.g.token, flask.g.srv_ac.sigkey_pub,
                                     objperm, objtype, error=True)

    # Log JSON
    json_in = flask.request.get_json(force=True)
    app.logger.debug("json_in = '{}'".format(json_in))

    # Get Required Attributes
    try:
        module_name = json_in['module_name']
    except KeyError as err:
        msg = "Missing required parameter: {}".format(err)
        app.logger.warning(msg)
        raise exceptions.MissingAttributeError(msg) from err

    # Get Optional Attributes
    uid = json_in.get('uid', None)
    module_kwargs = json_in.get('module_kwargs', {})
    userdata = json_in.get('userdata', {})

    # Log Attributes
    app.logger.debug("uid = '{}'".format(uid))
    app.logger.debug("module_name = '{}'".format(module_name))
    app.logger.debug("module_kwargs = '{}'".format(module_kwargs))
    app.logger.debug("userdata = '{}'".format(userdata))

    # Create Authenticator
    authenticator = flask.g.srv_ac.authenticators.create(key=uid, userdata=userdata,
                                                         module_name=module_name,
                                                         module_kwargs=module_kwargs)
    app.logger.debug("authenticator = '{}'".format(authenticator))

    # Return Response
    json_out = {_KEY_AUTHENTICATORS: [authenticator.key]}
    app.logger.debug("json_out = '{}'".format(json_out))
    return flask.jsonify(json_out)

@app.route("/{}/<authenticators_uid>/".format(_KEY_AUTHENTICATORS), methods=['GET'])
@authenticate_client()
@get_token()
def get_authenticators(authenticators_uid):

    app.logger.debug("GET AUTHENTICATORS")

    # Verify Tokens
    objperm = constants.PERM_READ
    objtype = constants.TYPE_AUTHENTICATOR
    objuid = uuid.UUID(authenticators_uid)
    utility.verify_auth_token_sigkey(flask.g.token, flask.g.srv_ac.sigkey_pub,
                                     objperm, objtype, objuid=objuid,
                                     error=True)

    # Get Authenticator
    authenticator = flask.g.srv_ac.authenticators.get(key=authenticators_uid)
    app.logger.debug("authenticator = '{}'".format(authenticator))

    # Return Response
    json_out = {'uid': authenticator.key,
                'module_name': authenticator.module_name,
                'module_kwargs': authenticator.module_kwargs,
                'userdata': authenticator.userdata}
    app.logger.debug("json_out = '{}'".format(json_out))
    return flask.jsonify(json_out)


## Verifier Endpoints ##

@app.route("/{}/".format(_KEY_VERIFIERS), methods=['POST'])
@authenticate_client()
@get_token()
def create_verifiers():

    app.logger.debug("POST VERIFIERS")

    # Verify Tokens
    objperm = constants.PERM_CREATE
    objtype = constants.TYPE_SRV_AC
    utility.verify_auth_token_sigkey(flask.g.token, flask.g.srv_ac.sigkey_pub,
                                     objperm, objtype, error=True)

    # Log JSON
    json_in = flask.request.get_json(force=True)
    app.logger.debug("json_in = '{}'".format(json_in))

    # Get Optional Attributes
    uid = json_in.get('uid', None)
    accounts = json_in.get('accounts', [])
    authenticators = json_in.get('authenticators', [])
    userdata = json_in.get('userdata', {})

    # Log Attributes
    app.logger.debug("uid = '{}'".format(uid))
    app.logger.debug("accounts = '{}'".format(accounts))
    app.logger.debug("authenticators = '{}'".format(authenticators))
    app.logger.debug("userdata = '{}'".format(userdata))

    # Create Verifier
    verifier = flask.g.srv_ac.verifiers.create(key=uid, userdata=userdata,
                                              accounts=accounts,
                                              authenticators=authenticators)
    app.logger.debug("verifier = '{}'".format(verifier))

    # Return Response
    json_out = {_KEY_VERIFIERS: [verifier.key]}
    app.logger.debug("json_out = '{}'".format(json_out))
    return flask.jsonify(json_out)

@app.route("/{}/<verifiers_uid>/".format(_KEY_VERIFIERS), methods=['GET'])
@authenticate_client()
@get_token()
def get_verifiers(verifiers_uid):

    app.logger.debug("GET VERIFIERS")

    # Verify Tokens
    objperm = constants.PERM_READ
    objtype = constants.TYPE_VERIFIER
    objuid = uuid.UUID(verifiers_uid)
    utility.verify_auth_token_sigkey(flask.g.token, flask.g.srv_ac.sigkey_pub,
                                     objperm, objtype, objuid=objuid,
                                     error=True)

    # Get Verifier
    verifier = flask.g.srv_ac.verifiers.get(key=verifiers_uid)
    app.logger.debug("verifier = '{}'".format(verifier))

    # Return Response
    json_out = {'uid': verifier.key,
                'accounts': list(verifier.accounts.by_uid()),
                'authenticators': list(verifier.authenticators.by_uid())}
    app.logger.debug("json_out = '{}'".format(json_out))
    return flask.jsonify(json_out)


## Permission Group Endpoints ##

@app.route("/{}/".format(_KEY_PERMISSIONS), methods=['POST'])
@authenticate_client()
@get_token()
def create_permissions():

    app.logger.debug("POST PERMISSIONS")

    # Verify Tokens
    objperm = constants.PERM_CREATE
    objtype = constants.TYPE_SRV_AC
    utility.verify_auth_token_sigkey(flask.g.token, flask.g.srv_ac.sigkey_pub,
                                     objperm, objtype, error=True)

    # Log JSON
    json_in = flask.request.get_json(force=True)
    app.logger.debug("json_in = '{}'".format(json_in))

    # Get Required Attributes
    try:
        objtype = json_in[constants.KEY_OBJTYPE]
    except KeyError as err:
        msg = "Missing required paremeter: {}".format(e)
        app.logger.warning(msg)
        raise exceptions.MissingAttributeError(msg) from err

    # Case by Obj Type
    app.logger.debug("objtype = '{}'".format(objtype))
    if objtype in constants.SRV_TYPES:
        objuid = None
    elif objtype in constants.UID_TYPES:
        try:
            objuid = json_in[constants.KEY_OBJUID]
            objuid = uuid.UUID(objuid)
        except KeyError as err:
            msg = "Missing required parameter: {}".format(err)
            app.logger.warning(msg)
            raise exceptions.MissingAttributeError(msg) from err
        else:
            app.logger.debug("objuid = '{}'".format(objuid))
    else:
        raise exceptions.UnknownObjType(objtype)
    app.logger.debug("objuid = '{}'".format(objuid))

    # Get Verifiers
    v_create = json_in.get(constants.PERM_CREATE, None)
    v_read = json_in.get(constants.PERM_READ, None)
    v_modify = json_in.get(constants.PERM_MODIFY, None)
    v_delete = json_in.get(constants.PERM_DELETE, None)
    v_perms = json_in.get(constants.PERM_PERMS, None)
    v_default = json_in.get(constants.PERM_DEFAULT, None)

    # Log Verfiers
    app.logger.debug("v_create = '{}'".format(v_create))
    app.logger.debug("v_read = '{}'".format(v_read))
    app.logger.debug("v_modify = '{}'".format(v_modify))
    app.logger.debug("v_delete = '{}'".format(v_delete))
    app.logger.debug("v_perms = '{}'".format(v_perms))
    app.logger.debug("v_default = '{}'".format(v_default))

    # Create Permissions
    perms = flask.g.srv_ac.permissions.create(objuid=objuid,
                                              objtype=objtype,
                                              v_create=v_create,
                                              v_read=v_read,
                                              v_modify=v_modify,
                                              v_delete=v_delete,
                                              v_perms=v_perms,
                                              v_default=v_default)
    app.logger.debug("perms = '{}'".format(perms))

    # Return Response
    perm_out = {constants.KEY_OBJTYPE: objtype}
    if objuid:
        perm_out[constants.KEY_OBJUID] = str(objuid)
    json_out = {_KEY_PERMISSIONS: [perm_out]}
    app.logger.debug("json_out = '{}'".format(json_out))
    return flask.jsonify(json_out)

@app.route("/{}/<objtype>/<objuid>/".format(_KEY_PERMISSIONS), methods=['GET'])
@authenticate_client()
@get_token()
def get_permissions(objtype, objuid):

    app.logger.debug("GET PERMISSIONS")

    # Get UUID if required
    if objtype in constants.SRV_TYPES:
        objuid = None
    if objtype in constants.UID_TYPES:
        objuid = uuid.UUID(objuid)
    else:
        raise exceptions.UnknownObjType(objtype)

    # Verify Tokens
    objperm = constants.PERM_PERMS
    utility.verify_auth_token_sigkey(flask.g.token, flask.g.srv_ac.sigkey_pub,
                                     objperm, objtype, objuid=objuid,
                                     error=True)

    # Get Permissions
    perms = flask.g.srv_ac.permissions.get(objtype=objtype, objuid=objuid)
    app.logger.debug("perms = '{}'".format(perms))

    # Build Response
    json_out = {'objtype': objtype,
                'objuid': str(objuid) if objuid else "",
                'create': list(perms.v_create.by_uid()),
                'read': list(perms.v_read.by_uid()),
                'modify': list(perms.v_modify.by_uid()),
                'delete': list(perms.v_delete.by_uid()),
                'perms': list(perms.v_perms.by_uid())}

    # Return Response
    app.logger.debug("json_out = '{}'".format(json_out))
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

@app.errorhandler(exceptions.SSLClientCertError)
def bad_clientcert(error):
    err = { 'status': 401,
            'message': "{}".format(error) }
    app.logger.info("Client Error: SSLClientCertError: {}".format(err))
    res = flask.jsonify(err)
    res.status_code = err['status']
    return res

@app.errorhandler(exceptions.AccountUIDError)
def bad_accountuid(error):
    err = { 'status': 401,
            'message': "{}".format(error) }
    app.logger.info("Client Error: AccountUIDError: {}".format(err))
    res = flask.jsonify(err)
    res.status_code = err['status']
    return res

@app.errorhandler(exceptions.ClientUIDError)
def bad_clientuid(error):
    err = { 'status': 401,
            'message': "{}".format(error) }
    app.logger.info("Client Error: ClientUIDError: {}".format(err))
    res = flask.jsonify(err)
    res.status_code = err['status']
    return res

@app.errorhandler(exceptions.SSLClientCertError)
def bad_cert(error):
    err = { 'status': 401,
            'message': "{}".format(error) }
    app.logger.info("Client Error: SSLClientCertError: {}".format(err))
    res = flask.jsonify(err)
    res.status_code = err['status']
    return res

@app.errorhandler(exceptions.TokensError)
def bad_tokens(error):
    err = { 'status': 401,
            'message': "{}".format(error) }
    app.logger.info("Client Error: TokensError: {}".format(err))
    res = flask.jsonify(err)
    res.status_code = err['status']
    return res

@app.errorhandler(utility.TokenVerificationFailed)
def failed_tokens(error):
    err = { 'status': 401,
            'message': "{}".format(error) }
    app.logger.info("Client Error: TokenVerificationFailed: {}".format(err))
    res = flask.jsonify(err)
    res.status_code = err['status']
    return res

@app.errorhandler(exceptions.MissingAttributeError)
def missing_attribute(error):
    err = { 'status': 400,
            'message': "{}".format(error) }
    app.logger.info("Client Error: MissingAttributeError: {}".format(err))
    res = flask.jsonify(err)
    res.status_code = err['status']
    return res

@app.errorhandler(exceptions.UnknownObjType)
def unknown_objtype(error):
    err = { 'status': 400,
            'message': "{}".format(error) }
    app.logger.info("Client Error: UnknownObjType: {}".format(err))
    res = flask.jsonify(err)
    res.status_code = err['status']
    return res

@app.errorhandler(exceptions.MissingDefaultVerifiers)
def missing_default_verifiers(error):
    err = { 'status': 400,
            'message': "{}".format(error) }
    app.logger.info("Client Error: MissingDefaultVerifiers: {}".format(err))
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
