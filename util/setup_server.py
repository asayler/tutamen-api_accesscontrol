#!/usr/bin/env python3

# Andy Sayler
# Copyright 2015


### Imports ###

import uuid
import datetime

from pcollections import drivers
from pcollections import backends

from pytutamen_server import accesscontrol

from api_accesscontrol import config


### Main ###

if __name__ == "__main__":

    # Setup Backend
    pdriver = drivers.RedisDriver(db=config.REDIS_DB)
    pbackend = backends.RedisAtomicBackend(pdriver)

    # Setup Server
    srv_ac = accesscontrol.AccessControlServer(pbackend,
                                               create=True,
                                               cn=config.CA_CN,
                                               country=config.CA_COUNTRY,
                                               state=config.CA_STATE,
                                               locality=config.CA_LOCALITY,
                                               organization=config.CA_ORGANIZATION,
                                               ou=config.CA_OU,
                                               email=config.CA_EMAIL)

    # Save Cert
    ca_crt_path = config.CA_CERT_PATH
    with open(ca_crt_path, 'w') as f:
        f.write(srv_ac.ca_cert)
