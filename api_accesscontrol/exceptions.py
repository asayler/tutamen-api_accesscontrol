# -*- coding: utf-8 -*-

# Andy Sayler
# Copyright 2015


### Imports ###


### API Exceptions ###

class APIError(Exception):
    pass

class TokensError(APIError):
    pass

class SSLError(APIError):
    pass

class SSLClientCertError(SSLError):
    pass

class AccountUIDError(SSLClientCertError):
    pass

class ClientUIDError(SSLClientCertError):
    pass

class MissingAttributeError(APIError):
    pass

class UnknownObjType(APIError):

    def __init__(self, objtype):
        msg = "Unknown objtyp '{}'".format(objtype)
        super().__init__(msg)

class MissingDefaultVerifiers(APIError):

    def __init__(self):
        msg = "Default verifiers required but not found"
        super().__init__(msg)
