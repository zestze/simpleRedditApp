#!/usr/bin/env python3
"""
simple python client for grabbing a users saved links by subreddit
"""

import requests
import requests.auth
import argparse

_USER_AGENT_ = "simpleRedditClient/0.1 by ZestyZeke"

def parse_response(response_dict, filter_subreddit):
    """
    response_dict['children'] is a list of children.
    Each has multiple attributes like
    url, title, subreddit, name
    """
    for child_dict in response_dict['children']:
        data_dict = child_dict['data']
        if filter_subreddit == "" or data_dict['subreddit'].lower() == filter_subreddit.lower():
            print ("https://www.reddit.com" + data_dict['permalink'])

    return response_dict['after']

def check_rate_limit(response):
    """
    Xused - used requests
    Xrem - remaining requests
    Xres - seconds to end of period
    """
    Xused = response.headers['X-Ratelimit-Used']
    Xrem = response.headers['X-Ratelimit-Remaining']
    Xres = response.headers['X-Ratelimit-Reset']
    if Xrem == "0": # note: is of type str
        raise RuntimeError("no remaining requests for this period") 
    return Xused, Xrem, Xres


class UserAPIobject:
    username = ""
    password = ""
    clientID = ""
    clientSecret = ""
    sessionToken = ""
    sessionTokenType = ""

    # for fun: interested in num of saved posts per subreddit
    subreddit_map = {}

    def __init__(self):
        with open('creds/client.id', 'r') as file1, \
                open('creds/client.secret', 'r') as file2, \
                open('creds/user.name', 'r') as file3, \
                open('creds/user.pass', 'r') as file4:
            self.clientID = file1.read().replace('\n', '')
            self.clientSecret = file2.read().replace('\n', '')
            self.username = file3.read().replace('\n', '')
            self.password = file4.read().replace('\n', '')

    def authorize(self):
        client_auth = requests.auth.HTTPBasicAuth(self.clientID, self.clientSecret)
        post_data = {"grant_type": "password", "username": self.username,
                     "password": self.password}
        headers = {"User-Agent": _USER_AGENT_}
        response = requests.post("https://www.reddit.com/api/v1/access_token",
                                 auth=client_auth, data=post_data,
                                 headers=headers)

        response_dict = response.json()
        self.sessionToken = response_dict['access_token']
        self.sessionTokenType = response_dict['token_type']

    def getFromAPI(self, requested_file, after=""):
        headers = {"Authorization": "{} {}".format(self.sessionTokenType,
                                                   self.sessionToken),
                   "User-Agent": _USER_AGENT_}
        uri = "https://oauth.reddit.com" + requested_file
        if after != "":
            uri += "?after={}".format(after)
        response = requests.get(uri, headers=headers)
        check_rate_limit(response) # for now, not doing anything with returned values 
        return response.json()

    def log_subreddit(self, response_dict):
        """
        response_dict['children'] is a list of children.
        Each has multiple attributes like
        url, title, subreddit, name
        """
        for child_dict in response_dict['children']:
            data_dict = child_dict['data']
            subreddit_name = data_dict['subreddit']
            if subreddit_name in self.subreddit_map:
                self.subreddit_map[subreddit_name] += 1
            else:
                self.subreddit_map[subreddit_name] = 1

    def print_subreddit_map(self):
        list_of_tuples = sorted(self.subreddit_map.items(),
                              key=lambda x: x[1],
                              reverse=True)
        for name, count in list_of_tuples:
            print ("{:<30}: {}".format(name, count))

    def run(self, filter_subreddit, show_map):
        self.authorize()

        requested_file = "/user/{}/saved".format(self.username)
        response_dict = self.getFromAPI(requested_file)

        after_set = set()
        after = parse_response(response_dict['data'], filter_subreddit)

        while after not in after_set:
            after_set.add(after)
            response_dict = self.getFromAPI(requested_file, after)
            after = parse_response(response_dict['data'], filter_subreddit)
            self.log_subreddit(response_dict['data'])

        if show_map:
            self.print_subreddit_map()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Reddit app to filter saved posts by subreddit")
    parser.add_argument('-f', '--filter', type=str, required=True,
                        help='The subreddit to filter on')
    parser.add_argument('-m', '--map', action='store_true',
                        help='set if you would like to see a category map of saved posts')

    args = parser.parse_args()
    userAPIobj = UserAPIobject()
    userAPIobj.run(args.filter, args.map)
