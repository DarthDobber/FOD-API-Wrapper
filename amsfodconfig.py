#!/usr/bin/env python

# If you have a proxy that you need to authenticate against, set 'use_Proxy' to
# True.  If use_Proxy is set to False the proxy settings are ignored and not used.
use_Proxy = True
# If your proxy requires authentication use this form:
# "http://<USERNAME>:<PASSWORD>@<FULLYQUALIFIEDPROXYSERVER>:<PORT>"
# If it doesn't need authentication use this form:
# "http://<FULLYQUALIFIEDPROXYSERVER>:<PORT>"
http_proxy  = "http://p074718:hannah55@proxy2.secure.protective.com:80"
https_proxy = "https://p074718:hannah55@proxy2.secure.protective.com:80"
ftp_proxy   = "ftp://p074718:hannah55@proxy2.secure.protective.com:80"

# Ignore this setting, this is the format used by the API
proxyDict = { 
              "http"  : http_proxy, 
              "https" : https_proxy, 
              "ftp"   : ftp_proxy
            }


# In order to use this tool, you will need a set of API Keys
# To get this information log into your portal, click administration
# then click the settings option and then click on 'API' or browse here:
# https://ams.fortify.com/Admin/Settings/ApiKeys
secret = "RjSKQ1-}OQgl5.d7rjnZ2wcqNqV9Jy"
apiKey = "acdd0eb9-076f-4938-8377-72087ed54c65"
token_url = "https://ams.fortify.com/oauth/token/"

# This is the location that you would like to save any information
# downloaded by this tool
down_loc = "C:\Temp"