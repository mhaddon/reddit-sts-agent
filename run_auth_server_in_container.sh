#!/usr/bin/env bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

echo "Building container..."
(cd auth_server && docker build -t "reddit_auth_server" --build-arg CLIENT_ID="${CLIENT_ID:-MkcLNaOSOME8mA}" . > /dev/null)

docker run -it \
    -p "${PORT:-65010}:${PORT:-65010}" \
    $([[ "${CLIENT_SECRET}" ]] && echo "-e \"CLIENT_SECRET=${CLIENT_SECRET}\"") \
    $([[ "${PORT}" ]] && echo "-e \"PORT=${PORT}\"") \
    $([[ "${CALLBACK_PATH}" ]] && echo "-e \"CALLBACK_PATH=${CALLBACK_PATH}\"") \
    $([[ "${USER_AGENT}" ]] && echo "-e \"USER_AGENT=${USER_AGENT}\"") \
    reddit_auth_server
