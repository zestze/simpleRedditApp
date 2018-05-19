#!/usr/bin/env python3
"""
"""

import requests
import requests.auth

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

def main():
    username, password, clientID, clientSecret = grabCredentials()

    client_auth = requests.auth.HTTPBasicAuth(clientID, clientSecret)
    post_data = {"grant_type": "password", "username": username, \
                 "password": password}
    headers = {"User-Agent": "simpleRedditClient/0.1 by ZestyZeke"}
    response = requests.post("https://www.reddit.com/api/v1/access_token", \
                             auth=client_auth, data = post_data, \
                             headers=headers)
    print (response.json())

if __name__ == "__main__":
    main()
