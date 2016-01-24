#!/usr/bin/env python3

# Andy Sayler
# Copyright 2015


### Imports ###

import uuid
import datetime

from pcollections import drivers
from pcollections import backends

from pytutamen_server import constants
from pytutamen_server import datatypes
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
        f.write(srv_ac.ca_crt)

    # Set Default Server Permissions
    try:
        srv_ac.permissions.get(objtype=constants.TYPE_SRV_AC)
    except  datatypes.ObjectDNE as err:
        print("AC Server Permissions Already Exist! Skipping...: {}".format(err))
    else:
        v = srv_ac.verifiers.create(bypass_accounts=True)
        srv_ac.permissions.create(objtype=constants.TYPE_SRV_AC,
                                  v_create=[v],
                                  v_read=[],
                                  v_modify=[],
                                  v_delete=[],
                                  v_perms=[])

    try:
        srv_ac.permissions.create(objtype=constants.TYPE_SRV_STORAGE)
    except  datatypes.ObjectDNE as err:
        print("Storage Server Permissions Already Exist! Skipping...: {}".format(err))
    else:
        v = srv_ac.verifiers.create(bypass_accounts=True)
        srv_ac.permissions.create(objtype=constants.TYPE_SRV_STORAGE,
                                  v_create=[v],
                                  v_read=[],
                                  v_modify=[],
                                  v_delete=[],
                                  v_perms=[])
