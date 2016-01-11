# Andy Sayler
# Copyright 2015

ECHO = @echo

GIT = git

APT = apt-get

PYTHON = python3
PIP = pip3
PYLINT = pylint

REQUIRMENTS = requirments.txt
PYLINT_CONF = pylint.rc

API_DIR = "./api_accesscontrol/"
TEST_DIR = "./tests/"

PYTHONPATH = $(shell readlink -f ./)
EXPORT_PATH = export PYTHONPATH="$(PYTHONPATH)"

TUTSRV_DIR = "./submodules/tutamen-pytutamen_server"

.PHONY: all git reqs conf lint test clean

all:
	$(ECHO) "This is a python project; nothing to build!"

git:
	$(GIT) submodule init
	$(GIT) submodule update

reqs:
	$(PIP) install -r $(REQUIRMENTS) -U
	$(APT) install libffi-dev libssl-dev
	$(MAKE) -C $(TUTSRV_DIR) reqs

conf:
	$(ECHO) "Todo"

lint:
	$(ECHO) "Todo"

test:
	$(ECHO) "Todo"

clean:
	$(RM) *~
	$(RM) $(API_DIR)/*~
	$(RM) $(API_DIR)/*.pyc
