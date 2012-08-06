#!/bin/bash
# Starts the gateway on the current machine
# Ensure that we actually are a gateway.
[[ -f ~/.gateway ]] || exit 0

echo Starting ARG
sudo insmod arg.ko

