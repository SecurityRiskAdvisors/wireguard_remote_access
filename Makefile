CONFIG_DIRECTORY=/etc/wireguard
APPLICATION_DIRECTORY=/opt/wireguard_remote_access
WG_BINARY=wg
PYTHON_BINARY=python3
CONFIG_FILE=config.ini
APP=wireguard_remote_access.py
CURRENT_DIR = $(shell pwd)
SHELL=/bin/bash
.DEFAULT_GOAL := check


check:
	pwd
	command -v $(PYTHON_BINARY)
	command -v $(WG_BINARY)
install:
	mkdir -p $(APPLICATION_DIRECTORY)
	mkdir -p $(CONFIG_DIRECTORY)
	cp -v $(CONFIG_FILE) $(CONFIG_DIRECTORY)
	cp -v $(APP) $(APPLICATION_DIRECTORY)
