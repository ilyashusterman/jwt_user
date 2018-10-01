################################################################################
# Makefile for user_jwt : testing
#############################################################################

# Prefer bash shell
export SHELL=/bin/bash

# Make sure of current python path
export PYTHONPATH=$(pwd)

ifneq (,$(VERBOSE))
    override VERBOSE:=
else
    override VERBOSE:=@
endif

.PHONY: test
test:
	$(VERBOSE) nosetests tests/TestUserAuthorization.py
.PHONY: smoke
smoke:
	$(VERBOSE) nosetests
# build commands:
# python setup.py sdist bdist_wheel
# twine upload dist/*
.PHONY: build_and_push
build_and_push:
	$(VERBOSE) rm -rf ./build
	$(VERBOSE) rm -rf ./dist
	$(VERBOSE) rm -rf ./jwt_user.egg-info
	$(VERBOSE) python setup.py sdist bdist_wheel
	$(VERBOSE) twine upload dist/*
