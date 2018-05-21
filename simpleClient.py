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

def parse_response(responseDict):
    for childDict in responseDict['children']:
        dataDict = childDict['data']
        print ("https://www.reddit.com" + dataDict['permalink'])

        # print url, title and subreddit
        #print ("url: " + dataDict['url'])
        #print ("title: " + dataDict['title'])
        #print ("subreddit: " + dataDict['subreddit'])
        #print ("name: " + dataDict['name'])
    print (responseDict.keys())
    done = False
    if len(responseDict['children']) == 0:
        done = True
    return responseDict['after'], done

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

def check_rate_limit(response):
    Xused = response.headers['X-Ratelimit-Used']
    Xrem = response.headers['X-Ratelimit-Remaining']
    Xres = response.headers['X-Ratelimit-Reset']
    if Xrem == "0": # note: is of type str
        raise RuntimeError("no remaining requests for this period") 
    print ("Used Requests: " + Xused)
    print ("Remaining Requests: " + Xrem)
    print ("Seconds to end of period: " + Xres)
    return Xused, Xrem, Xres

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
    response = requests.get("https://oauth.reddit.com/user/ZestyZeke/saved", \
                            headers=headers)
    Xused, Xrem, Xres = check_rate_limit(response)
    responseDict = response.json()
    afterSet = set()
    after, done = parse_response(responseDict['data'])
    afterSet.add(after)
    while not done:
        response = requests.get("https://oauth.reddit.com/user/ZestyZeke/saved" \
                                 + "?after={}".format(after), \
                                 headers=headers)
        Xused, Xrem, Xres = check_rate_limit(response)
        responseDict = response.json()
        after, done = parse_response(responseDict['data'])
        if after in afterSet:
            break
        else:
            afterSet.add(after)

if __name__ == "__main__":
    main()
