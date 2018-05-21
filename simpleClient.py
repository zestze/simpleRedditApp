#!/usr/bin/env python3
"""
"""

import requests
import requests.auth
import string
import re

_USER_AGENT_ = "simpleRedditClient/0.1 by ZestyZeke"

def grabCredentials():
    p = ""
    u = ""
    cI = ""
    cS = ""
    with open('client.id', 'r') as myFile:
        cI = myFile.read().replace('\n', '')
    with open('client.secret', 'r') as myFile:
        cS = myFile.read().replace('\n', '')
    with open('user.name', 'r') as myFile:
        u = myFile.read().replace('\n', '')
    with open('user.pass', 'r') as myFile:
        p = myFile.read().replace('\n', '')
    return u, p, cI, cS

def parse_json(responseDict):
    for childDict in responseDict['children']:
        # note: each one of these is a dict
        #print (childDict['title'])
        #for key, val in childDict.items():
        #    print (key)
        #for key, val in childDict['data'].items():
        #    print (key)
        dataDict = childDict['data']
        print (type(dataDict))
        print ("https://www.reddit.com" + dataDict['permalink'])
        #for key, val in dataDict.items():
            #print ("key: " + key)
            #print ("value: " + str(val))

        # print url, title and subreddit
        #print ("url: " + dataDict['url'])
        #print ("title: " + dataDict['title'])
        #print ("subreddit: " + dataDict['subreddit'])
        #print ("name: " + dataDict['name'])
        #print (childDict)
        #try:
            #url = give_url(dataDict['subreddit'], dataDict['title'], dataDict['name'])
        #except Exception as e:
        #    raise e
        #print (url)

def give_url(subreddit, title, name):
    """
    format is
    https://www.reddit.com/r/<subredditWithCaps>/comments/<partOfName>/<title_no_caps>
    the name should be something like <t3_id>, <partOfName> refers to the 'id' part
    the <title_no_caps> should also replace spaces with underscores
    """
    url = "https://www.reddit.com/r/{}/comments/".format(subreddit)
    nameID = name[name.find("_")+1:]
    title = title.lower().replace(' ', '_')
    punct = string.punctuation.replace('_', '')
    punct += "|"

    outtab = ''.join(["+" for p in punct])

    title = title.translate(str.maketrans(punct, outtab))
    title = title.replace('+', '')

    title = re.sub('_+', '_', title)
    title = title[:48]
    if title[-1] == "_":
        title = title[:len(title) - 1]
    if title[0] == "_":
        title = title[1:]

    url += "{}/{}".format(nameID, title)

    return url

def main():
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

    headers = {"Authorization": "{} {}".format(tokenType, token), \
               "User-Agent": _USER_AGENT_}
    response = requests.get("https://oauth.reddit.com/user/ZestyZeke/saved?show=all", \
                            headers=headers)
    responseDict = response.json()
    parse_json(responseDict['data'])

if __name__ == "__main__":
    main()
