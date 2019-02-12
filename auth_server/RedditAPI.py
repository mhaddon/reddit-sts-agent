from uuid import uuid4
import requests
import requests.auth
import urllib
import logging


class RedditAPI:
    def __init__(self, client_id, client_secret, redirect_url, scope, user_agent):
        self._client_id = client_id
        self._client_secret = client_secret
        self._redirect_url = redirect_url
        self._scope = scope
        self._user_agent = user_agent

    def _get_generic_header(self):
        return {"User-Agent": self._user_agent}

    def get_auth_url(self):
        return "https://ssl.reddit.com/api/v1/authorize?" + urllib.urlencode({
            "client_id": self._client_id,
            "response_type": "code",
            "state": str(uuid4()),  # todo: persist state uuid to validate that we are the source of the request
            "redirect_uri": self._redirect_url,
            "duration": "permanent",
            "scope": self._scope
        })

    def get_token(self, code):
        client_auth = requests.auth.HTTPBasicAuth(self._client_id, self._client_secret)
        post_data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self._redirect_url

        }

        response = None

        try:
            response = requests.post(
                "https://ssl.reddit.com/api/v1/access_token",
                auth=client_auth,
                headers=self._get_generic_header(),
                data=post_data
            )

            response.raise_for_status()

            return response.json()
        except TypeError as e:
            logging.error("Error parsing response: %s" % response.text)
            raise e
        except requests.exceptions.Timeout as e:
            logging.error("Timeout for access_token request")
            raise e
        except requests.exceptions.HTTPError as e:
            logging.error("Http error with status code: {status_code}, and response {response}".format(
                status_code=response.status_code,
                response=response.text
            ))
            raise e
