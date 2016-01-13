# -*- coding: utf-8 -*-

# Andy Sayler
# Copyright 2015


import configparser
import os


config = configparser.SafeConfigParser(allow_no_value=True)


# Sections

SEC_REDIS = "redis"
config.add_section(SEC_REDIS)
SEC_LOGGING = "logging"
config.add_section(SEC_LOGGING)
SEC_BOOTSTRAP = "bootstrap"
config.add_section(SEC_BOOTSTRAP)

# Filenames and Paths

MOD_PATH = os.path.dirname(os.path.realpath(__file__))
PROJ_DIR = os.path.realpath("{}/..".format(MOD_PATH))

CONF_DIR = os.path.realpath("/etc/tutamen/")
CONF_FILENAME = "tutamen_api_ac.conf"
CONF_PATHS = [os.path.join(CONF_DIR, CONF_FILENAME),
              os.path.join(PROJ_DIR, CONF_FILENAME)]

LOG_DIR = os.path.realpath("/var/log/tutamen/")
LOG_FILENAME = "tutamen_api_ac.log"
LOG_PATH = os.path.join(LOG_DIR, LOG_FILENAME)

# Default Vals

config.set(SEC_REDIS, 'HOST', "localhost")
config.set(SEC_REDIS, 'PORT', "6379")
config.set(SEC_REDIS, 'DB', "4")
config.set(SEC_REDIS, 'PASSWORD', None)


config.set(SEC_LOGGING, 'ENABLED', "True")
config.set(SEC_LOGGING, 'PATH', LOG_PATH)

config.set(SEC_BOOTSTRAP, 'PASSWORD', None)

# Read Config File

for path in CONF_PATHS:
    if os.path.isfile(path):
        config.read(path)
        break

# Get Vales with Env Overrides

REDIS_HOST = os.environ.get('TUTAMEN_API_AC_REDIS_HOST',
                            config.get(SEC_REDIS, 'HOST'))
REDIS_PORT = int(os.environ.get('TUTAMEN_API_AC_REDIS_PORT',
                                config.get(SEC_REDIS, 'PORT')))
REDIS_DB = int(os.environ.get('TUTAMEN_API_AC_REDIS_DB',
                              config.get(SEC_REDIS, 'DB')))
REDIS_PASSWORD = os.environ.get('TUTAMEN_API_AC_REDIS_PASSWORD',
                                config.get(SEC_REDIS, 'PASSWORD'))

LOGGING_ENABLED = os.environ.get('TUTAMEN_API_AC_LOGGING_ENABLED',
                                 config.get(SEC_LOGGING, 'ENABLED'))
LOGGING_ENABLED = LOGGING_ENABLED.lower() in ['true', 'yes', 'on', '1']
LOGGING_PATH = os.environ.get('TUTAMEN_API_AC_LOGGING_PATH',
                              config.get(SEC_LOGGING, 'PATH'))
LOGGING_PATH = os.path.realpath(LOGGING_PATH)

BOOTSTRAP_PASSWORD = os.environ.get('TUTAMEN_API_AC_BOOTSTRAP_PASSWORD',
                                    config.get(SEC_BOOTSTRAP, 'PASSWORD'))
