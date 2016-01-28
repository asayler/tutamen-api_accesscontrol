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
    srv_ac = accesscontrol.AccessControlServer(pbackend, create=False)

    for authz_key in srv_ac.authorizations.by_key():

        try:
            print("Loading Authz '{}'".format(authz_key))
            authz = srv_ac.val_to_obj(authz_key,
                                      srv_ac.authorizations.type_child,
                                      pindex=srv_ac.authorizations)
        except Exception as error:
            print(error)        

        try:
            print("Removing '{}'".format(authz))
            authz.destroy()
        except Exception as error:
            print(error)
    
