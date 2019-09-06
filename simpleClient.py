#!/usr/bin/env python3
"""
simple python client for grabbing a users saved links by subreddit
"""

import requests
import requests.auth
import string
import re
import sys

_USER_AGENT_ = "simpleRedditClient/0.1 by ZestyZeke"

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

    return responseDict['after']

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
        client_auth = requests.auth.HTTPBasicAuth(self.clientID, self.clientSecret)
        post_data = {"grant_type": "password", "username": self.username,
                     "password": self.password}
        headers = {"User-Agent": _USER_AGENT_}
        response = requests.post("https://www.reddit.com/api/v1/access_token",
                                 auth=client_auth, data=post_data,
                                 headers=headers)

        responseDict = response.json()
        self.sessionToken = responseDict['access_token']
        self.sessionTokenType = responseDict['token_type']

    def getFromAPI(self, requestedFile, after=""):
        headers = {"Authorization": "{} {}".format(self.sessionTokenType,
                                                   self.sessionToken),
                   "User-Agent": _USER_AGENT_}
        uri = "https://oauth.reddit.com" + requestedFile
        if after != "":
            uri += "?after={}".format(after)
        response = requests.get(uri, headers=headers)
        check_rate_limit(response) # for now, not doing anything with returned values 
        return response.json()

    def run(self, filterSubreddit):
        self.authorize()

        requestedFile = "/user/{}/saved".format(self.username)
        responseDict = self.getFromAPI(requestedFile)

        afterSet = set()
        after = parse_response(responseDict['data'], filterSubreddit)
        afterSet.add(after)

        while True:
            responseDict = self.getFromAPI(requestedFile, after)
            after = parse_response(responseDict['data'], filterSubreddit)
            if after in afterSet:
                break
            else:
                afterSet.add(after)

if __name__ == "__main__":
    if len(sys.argv) > 2:
        print ("Usage: python3 simpleClient.py [filterSubreddit]")
    else:
        userAPIobj = UserAPIobject()
        if len(sys.argv) == 2:
            userAPIobj.run(sys.argv[1])
        else:
            userAPIobj.run("hunterxhunter")
