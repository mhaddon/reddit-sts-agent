#!/usr/bin/env bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

CLIENT_ID="${CLIENT_ID:-MkcLNaOSOME8mA}" python "${DIR}/auth_server/server.py"