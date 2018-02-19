import requests
import amsfodconfig as cfg
import json

#Get the Authentication token
def getToken():
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    params = {"grant_type": "client_credentials", "scope": "https://hpfod.com/tenant", "client_id": cfg.apiKey, "client_secret": cfg.secret}

    if cfg.use_Proxy:
        r = requests.post(cfg.token_url, headers=headers, data=params, proxies=cfg.proxyDict)
    else:
        r = requests.post(cfg.token_url, headers=headers, data=params)
    #json.loads turns the json response into a dictionary
    data = json.loads(r.text)
    return data['access_token']

def getHeader():
    headerValue = "Bearer " + getToken()
    return headerValue
