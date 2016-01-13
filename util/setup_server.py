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


if __name__ == "__main__":

    pdriver = drivers.RedisDriver(db=config.REDIS_DB)
    pbackend = backends.RedisAtomicBackend(pdriver)
    srv_ac = accesscontrol.AccessControlServer(pbackend,
                                               create=True,
                                               cn=config.CA_CN,
                                               country=config.CA_COUNTRY,
                                               state=config.CA_STATE,
                                               locality=config.CA_LOCALITY,
                                               organization=config.CA_ORGANIZATION,
                                               ou=config.CA_OU,
                                               email=config.CA_EMAIL)
