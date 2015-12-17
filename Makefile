# Andy Sayler
# Copyright 2015

ECHO = @echo

GIT = git

PYTHON = python3
PIP = pip3
PYLINT = pylint

REQUIRMENTS = requirments.txt
PYLINT_CONF = pylint.rc

API_DIR = "./accesscontrol-api/"
TEST_DIR = "./tests/"

PYTHONPATH = $(shell readlink -f ./)
EXPORT_PATH = export PYTHONPATH="$(PYTHONPATH)"

.PHONY: all git reqs conf lint test clean

all:
	$(ECHO) "This is a python project; nothing to build!"

git:
	$(GIT) submodule init
	$(GIT) submodule update

reqs:
	$(PIP) install -r $(REQUIRMENTS) -U
	$(MAKE) -C $(PCOL_DIR) reqs3

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
