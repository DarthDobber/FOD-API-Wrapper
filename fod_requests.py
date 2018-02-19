import requests
import amsfodconfig as cfg
import json
from fod_token import getHeader

headerValue = getHeader()

class fodRequest:
    proxyDict = {}
    headers = {'Content-Type': 'application/json','Accept': 'application/json', 'Authorization': headerValue}
    params = {}
    data = {}
    c_header = False
    c_params = False
    c_data = False

    def __init__(self):
        if cfg.use_Proxy:
            self.proxyDict = cfg.proxyDict        

    def get(self, url, **kwargs):
        # Looking for headers, params, and data within kwargs
        if 'headers' in kwargs:
            self.headers = kwargs['headers']
            self.c_header = True
        if 'params' in kwargs:
            self.params = kwargs['params']
            self.c_params = True
        if 'data' in kwargs:
            self.data = kwargs['data']
            self.c_data = True        
       
        # If a Proxy server is in use, use these
        if cfg.use_Proxy:
            if self.c_data and self.c_params:
                r = requests.get(url, headers=self.headers, json=self.json_var, data=self.data, proxies=self.proxyDict)
            elif self.c_params:
                r = requests.get(url, headers=self.headers, json=self.params, proxies=self.proxyDict)
            elif self.c_data:
                r = requests.get(url, headers=self.headers, data=self.data, proxies=self.proxyDict)
            else:
                r = requests.get(url, headers=self.headers, proxies=self.proxyDict)
        # If no proxy server is needed, use these
        else:
            if self.c_data and self.c_params:
                r = requests.get(url, headers=self.headers, json=self.json_var, data=self.data)
            elif self.c_params:
                r = requests.get(url, headers=self.headers, json=self.params)
            elif self.c_data:
                r = requests.get(url, headers=self.headers, data=self.data)
            else:
                r = requests.get(url, headers=self.headers)

        data = json.loads(r.text)
        return data

    def post(self, url, **kwargs):
        pass

    def put(self, url, **kwargs):
        pass
    
    def delete(self, url, **kwargs):
        pass

