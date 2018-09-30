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
	$(VERBOSE) nosetests test/test_user_authorization.py
.PHONY: smoke
smoke:
	$(VERBOSE) nosetests /
