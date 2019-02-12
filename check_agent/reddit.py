import json
import math
import requests
import time
import datetime
from checks import AgentCheck
from hashlib import md5


class AccessToken:
    token = None
    duration = 0
    issued_at = 0
    expires_at = 0
    expires_buffer = 15

    def __init__(self, token, duration):
        self.issued_at = math.ceil(time.time())
        self.token = token
        self.duration = duration
        self.expires_at = self.issued_at + duration

    def is_valid(self):
        return self.token is not None and self.expires_at - self.expires_buffer > time.time() > self.issued_at


class RedditCheck(AgentCheck):
    CHECK_NAME = "reddit"

    def check(self, instance):
        self._check_config(instance)

        refresh_token = instance.get("refresh_token")
        access_token = self._obtain_new_access_token(refresh_token)

        username = self._get_username(access_token)

        self.count(
            'stackstatemessages.count',
            len(self._get_all_messages_referencing_stackstate(access_token)),
            tags=["username: %s" % username]
        )

        new_messages = self._get_recent_messages(access_token)

        if len(new_messages) > 0:
            self.event({
                'timestamp': int(time.time()),
                'event_type': 'new_messages',
                'msg_title': "{amount} new messages for user {username}".format(
                    amount=len(new_messages),
                    username=username
                ),
                'msg_text': json.dumps(new_messages),
                'aggregation_key': username
            })

        self.service_check(check_name=self.CHECK_NAME, status=AgentCheck.OK)

    def _get_recent_messages(self, access_token):
        last_collection_time_utc = int(datetime.datetime.utcnow().strftime("%s")) - \
                                   self.init_config.get("min_collection_interval", 20)
        return self._recursively_get_messages(
            access_token=access_token,
            filter_query=lambda entry:
            entry.get("data", {}).get("created_utc", 0) > last_collection_time_utc
        )[:10]

    def _get_api_url(self, path):
        return "https://oauth.reddit.com/{path}".format(path=path)

    def _get_generic_header(self):
        return {"User-Agent": self.init_config.get("client_agent", "sts-agent")}

    def _query_access_token(self, refresh_token):

        refresh_endpoint = "https://www.reddit.com/api/v1/access_token"
        payload_template = "grant_type=refresh_token&refresh_token={TOKEN}"

        client_auth = requests.auth.HTTPBasicAuth(self.init_config.get('client_id'), "")
        post_data = payload_template.format(TOKEN=refresh_token)
        response = None

        try:
            response = requests.post(
                refresh_endpoint,
                auth=client_auth,
                headers=self._get_generic_header(),
                data=post_data,
                timeout=self.init_config.get('default_timeout', 5)
            )

            response.raise_for_status()
            return response.json()
        except TypeError as e:
            self._parse_error(refresh_endpoint, response.text)
            raise e
        except requests.exceptions.Timeout as e:
            self._timeout_error(refresh_endpoint, self.init_config.get('default_timeout', 5))
            raise e
        except requests.exceptions.HTTPError as e:
            self._http_error(refresh_endpoint, response.status_code, response.text)
            raise e

    def _query_api(self, access_token, path):
        headers = self._get_generic_header()
        headers.update({"Authorization": "bearer " + access_token.token})
        endpoint = self._get_api_url(path)
        response = None

        try:
            response = requests.get(
                endpoint,
                headers=headers,
                timeout=self.init_config.get('default_timeout', 5)
            )
            response.raise_for_status()
            return response.json()
        except TypeError as e:
            self._parse_error(endpoint, response.text)
            raise e
        except requests.exceptions.Timeout as e:
            self._timeout_error(endpoint, self.init_config.get('default_timeout', 5))
            raise e
        except requests.exceptions.HTTPError as e:
            self._http_error(endpoint, response.status_code, response.text)
            raise e

    def _obtain_new_access_token(self, refresh_token):
        access_token_query = self._query_access_token(refresh_token)
        return AccessToken(access_token_query.get("access_token"), access_token_query.get("expires_in"))

    def _config_entry_not_found(self, message):
        self.log.error(message)
        self.service_check(check_name=self.CHECK_NAME, status=AgentCheck.WARNING, message=message)
        raise LookupError(message)

    def _check_config(self, instance):
        if 'refresh_token' not in instance:
            self._config_entry_not_found("Skipping instance, no refresh_token found.")

        if 'client_id' not in self.init_config:
            self._config_entry_not_found("Skipping instance, no client_id found.")

    def _merge_messages_uniquely(self, message_list_one, message_list_two):
        merged_list = dict(
            (item.get("data", {}).get("id", "_"), item) for item in message_list_one + message_list_two
        ).values()

        return sorted(
            merged_list,
            key=lambda key: key.get("data", {}).get("created", 0),
            reverse=True
        )

    def _recursively_get_messages(self, access_token, filter_query=None, limit_per_page=100, after=None):
        endpoint = "message/inbox?limit={limit}{after}".format(
            limit=limit_per_page,
            after=("&after=%s" % after if after is not None else "")
        )
        response = self._query_api(access_token, endpoint)
        next_after = response.get("data", {}).get("after", None)
        messages = response.get("data", {}).get("children", [])
        filtered_messages = messages if filter_query is None else list(filter(filter_query, messages))
        if next_after is not None:
            return self._merge_messages_uniquely(
                filtered_messages,
                self._recursively_get_messages(
                    access_token=access_token,
                    filter_query=filter_query,
                    limit_per_page=limit_per_page,
                    after=next_after
                )
            )
        return filtered_messages

    def _get_all_messages_referencing_stackstate(self, access_token):
        return self._recursively_get_messages(
            access_token=access_token,
            filter_query=lambda entry:
            "stackstate" in entry.get("data", {}).get("body", "").lower()
        )

    def _get_username(self, access_token):
        return self._query_api(access_token, "api/v1/me").get("name", "Unknown User")

    def _parse_error(self, url, response):
        message = "Failed to process response from endpoint: {endpoint}, response: {response}".format(
            endpoint=url,
            response=response
        )

        self.service_check(
            check_name=self.CHECK_NAME,
            status=AgentCheck.CRITICAL,
            message=message
        )

        self.event({
            'timestamp': int(time.time()),
            'event_type': 'http_check',
            'msg_title': 'Parse Failed',
            'msg_text': message,
            'aggregation_key': md5(url).hexdigest()
        })

    def _timeout_error(self, url, timeout):
        message = "Request timeout for endpoint: {endpoint}, timeout: {timeout}".format(
            endpoint=url,
            timeout=timeout
        )

        self.service_check(
            check_name=self.CHECK_NAME,
            status=AgentCheck.WARNING,
            message=message
        )

        self.event({
            'timestamp': int(time.time()),
            'event_type': 'http_check',
            'msg_title': 'URL timeout',
            'msg_text': message,
            'aggregation_key': md5(url).hexdigest()
        })

    def _http_error(self, url, status, message):
        message = "Failed to query endpoint: {endpoint}, with error status: {status}, and response: {response}".format(
            endpoint=url,
            status=status,
            response=message
        )

        self.service_check(
            check_name=self.CHECK_NAME,
            status=AgentCheck.CRITICAL,
            message=message
        )

        self.event({
            'timestamp': int(time.time()),
            'event_type': 'http_check',
            'msg_title': 'Server error',
            'msg_text': message,
            'aggregation_key': md5(url).hexdigest()
        })


if __name__ == '__main__':
    check, instances = RedditCheck.from_yaml('/etc/sts-agent/conf.d/reddit.yaml')
    for instance in instances:
        print "\nRunning the check against refresh_token: %s" % (instance['refresh_token'])
        check.check(instance)
        if check.has_events():
            print 'Events: %s' % (check.get_events())
        print 'Metrics: %s' % (check.get_metrics())
