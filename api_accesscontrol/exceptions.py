# -*- coding: utf-8 -*-

# Andy Sayler
# Copyright 2015


### Imports ###


### API Exceptions ###

class APIError(Exception):
    pass

class SSLError(APIError):
    pass

class SSLClientCertError(SSLError):
    pass
