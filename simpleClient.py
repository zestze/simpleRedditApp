#!/usr/bin/env python3
"""
simple python client for grabbing a users saved links by subreddit

@TODO: replace ZestyZeke with username vals
"""

import requests
import requests.auth
import string
import re
import sys

_USER_AGENT_ = "simpleRedditClient/0.1 by ZestyZeke"

class UserAPIobject:
    username = ""
    password = ""
    clientID = ""
    clientSecret = ""
    def __init__(self):
        with open('client.id', 'r') as file1, \
                open('client.secret', 'r') as file2, \
                open('user.name', 'r') as file3, \
                open('user.pass', 'r') as file4:
            self.clientID = file1.read().replace('\n', '')
            self.clientSecret = file2.read().replace('\n', '')
            self.username = file3.read().replace('\n', '')
            self.password = file4.read().replace('\n', '')

    def authorize(self):
        client_auth = requests.auth.HTTPBasicAuth(clientID, clientSecret)
        post_data = {"grant_type": "password", "username": self.username,
                     "password": self.password}
        headers = {"User-Agent": _USER_AGENT_}
        response = requests.post("https://www.reddit.com/api/v1/access_token",
                                 auth=client_auth, data=post_data,
                                 headers=headers)

def parse_response(responseDict, filterSubreddit):
    """
    responseDict['children'] is a list of children.
    Each has multiple attributes like
    url, title, subreddit, name
    """
    for childDict in responseDict['children']:
        dataDict = childDict['data']
        if filterSubreddit == "" or dataDict['subreddit'].lower() == filterSubreddit.lower():
            print ("https://www.reddit.com" + dataDict['permalink'])

    done = False
    if len(responseDict['children']) == 0:
        done = True
    return responseDict['after'], done

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

def authorize():
    username, password, clientID, clientSecret = grabCredentials()

    client_auth = requests.auth.HTTPBasicAuth(clientID, clientSecret)
    post_data = {"grant_type": "password", "username": username, \
                 "password": password}
    headers = {"User-Agent": _USER_AGENT_ }
    response = requests.post("https://www.reddit.com/api/v1/access_token", \
                             auth=client_auth, data = post_data, \
                             headers=headers)

    responseDict = response.json()
    token = responseDict['access_token']
    tokenType = responseDict['token_type']

    return tokenType, token

def main(filterSubreddit=""):
    tokenType, token = authorize()

    headers = {"Authorization": "{} {}".format(tokenType, token), \
               "User-Agent": _USER_AGENT_}
    response = requests.get("https://oauth.reddit.com/user/ZestyZeke/saved", \
                            headers=headers)
    Xused, Xrem, Xres = check_rate_limit(response)
    responseDict = response.json()
    afterSet = set()
    after, done = parse_response(responseDict['data'], filterSubreddit)
    afterSet.add(after)
    while not done:
        response = requests.get("https://oauth.reddit.com/user/ZestyZeke/saved" \
                                 + "?after={}".format(after), \
                                 headers=headers)
        Xused, Xrem, Xres = check_rate_limit(response)
        responseDict = response.json()
        after, done = parse_response(responseDict['data'], filterSubreddit)
        if after in afterSet:
            break
        else:
            afterSet.add(after)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        f = "hunterxhunter"
        #f = "youtubehaiku"
        main(f)
    else:
        main(sys.argv[1])
