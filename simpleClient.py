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

    # for fun: interested in num of saved posts per subreddit
    subredditMap = {}

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

    def logSubreddit(self, responseDict):
        """
        responseDict['children'] is a list of children.
        Each has multiple attributes like
        url, title, subreddit, name
        """
        for childDict in responseDict['children']:
            dataDict = childDict['data']
            subredditName = dataDict['subreddit']
            if subredditName in self.subredditMap:
                self.subredditMap[subredditName] += 1
            else:
                self.subredditMap[subredditName] = 1

    def printSubredditMap(self):
        listOfTuples = sorted(self.subredditMap.items(), 
                              key=lambda x: x[1],
                              reverse=True)
        for name, count in listOfTuples:
            print ("{:<30}: {}".format(name, count))

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
            self.logSubreddit(responseDict['data'])
            if after in afterSet:
                break
            else:
                afterSet.add(after)

        # prompt user to see if they'd like to see a 
        # category map of their saves posts
        response = input("Would you like to see your subreddit map? [Y\\N]: ")
        if response == "Y" or response == "y":
            self.printSubredditMap()

if __name__ == "__main__":
    if len(sys.argv) > 2:
        print ("Usage: python3 simpleClient.py [filterSubreddit]")
        sys.exit() # exit early

    try:
        userAPIobj = UserAPIobject()
        if len(sys.argv) == 2:
            userAPIobj.run(sys.argv[1])
        else:
            userAPIobj.run("hunterxhunter")

    except KeyboardInterrupt:
        print ("exiting...")
    finally:
        sys.exit()
