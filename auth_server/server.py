#!/usr/bin/env python
from flask import Flask, abort, request
from RedditAPI import RedditAPI
import os

if "CLIENT_ID" not in os.environ:
    raise Exception("Environment 'CLIENT_ID' missing")


PORT = os.getenv("PORT", 65010)
CALLBACK_PATH = os.getenv("CALLBACK_PATH", "reddit_callback")

api = RedditAPI(
    client_id=os.environ['CLIENT_ID'],
    client_secret=os.getenv("CLIENT_SECRET", ""),
    redirect_url="http://localhost:{port}/{callback_path}".format(port=PORT, callback_path=CALLBACK_PATH),
    scope="identity privatemessages",
    user_agent=os.getenv("USER_AGENT", "sts-agent")
)

app = Flask(__name__)


def style():
    return ';'.join(map(str, [
        "position: absolute",
        "top: 15%",
        "left: 50%",
        "transform: translateX(-50%)",
        "background: #6e8e88",
        "color: #efefef",
        "text-decoration: none",
        "padding: 12px 15px",
        "font-family: sans-serif"
    ]))


@app.route('/')
def homepage():
    return '<a href="{url}" style="{style}">Authenticate</a>'.format(
        url=api.get_auth_url(),
        style=style()
    )


@app.route("/{callback_path}".format(callback_path=CALLBACK_PATH))
def callback():
    error = request.args.get('error', '')
    if error:
        return "Error: " + error

    code = request.args.get('code')
    token_json = api.get_token(code)

    if "refresh_token" in token_json:
        return "Your refresh token is: %s" % token_json.get("refresh_token")
    else:
        return homepage()


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=PORT)
