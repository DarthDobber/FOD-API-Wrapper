from fod_requests import fodRequest
from fod_token import getHeader
from amsfod import getReleaseIDLatest
from ams_defaults import getAppMonVulns

headerValue = getHeader()

s = fodRequest()
# p = s.get("https://api.iextrading.com/1.0/stock/aapl/earnings")
# print(p)

# getRelease_url = "https://api.ams.fortify.com/api/v3/releases/142269"
# headers = {"Accept": "application/json", "Authorization": headerValue}
# params = {"filters": "applicationId:67007"}

# z = s.get(getRelease_url, headers=headers, sam=params, bob=params)
# print(z)

# listapp_url = "https://api.ams.fortify.com/api/v3/applications/"
# headers = {"Accept": "application/json", "Authorization": headerValue}
# params = {'fields': 'applicationID,applicationName'}

# q = s.get(listapp_url, headers=headers, params=params)
# print(q)

# releaseID = 0
# appID = str(6294)
# getRelease_url = "https://api.ams.fortify.com/api/v3/applications/{appID}/releases".format(appID=appID)
# headers = {"Accept": "application/json", "Authorization": headerValue}
# #params = {"filters": "applicationId:"+ str(appID)}

# r = s.get(getRelease_url, headers=headers)
# # for release in r['items']:
# #     if release['releaseId'] > releaseID:
# #         releaseID = release['releaseId']

# print(r)

r = getAppMonVulns(67007, limit=1, offset=1, fields="findingId,severityId")
print(r)



