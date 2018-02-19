import amsfodconfig as cfg
import requests
import json
import time
import datetime
from prettytable import PrettyTable, from_csv
import csv

class appinfo:
    def __init__(self, appName, appID):
        self.appName = appName
        self.appID = appID
    
    def addinfo(self, lastRelease, lastScan, releaseName):
        self.lastScan = lastScan
        self.lastRelease = lastRelease
        self.releaseName = releaseName

class vulninfo:
    def __init__(self, severity, kingdom, category, cwe, location, scanDate):
        self.severity = severity
        self.kingdom = kingdom
        self.category = category
        self.cwe = cwe
        self.location = location
        self.scanDate = scanDate

        if self.severity == 'Critical':
            self.sevCode = 1
        elif self.severity == 'High':
            self.sevCode = 2
        elif self.severity == 'Medium':
            self.sevCode = 3
        elif self.severity == 'Low':
            self.sevCode = 4
        elif self.severity == 'Best Practice':
            self.sevCode = 5
        elif self.severity == 'Info':
            self.sevCode = 6
        else:
            self.sevCode = 7
    
    def addinfo(self, appName):
        self.appName = appName

#Get the Authentication token
def getToken():
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    params = {"grant_type": "client_credentials", "scope": "https://hpfod.com/tenant", "client_id": apiKey, "client_secret": secret}

    r = requests.post(token_url, headers=headers, data=params, proxies=proxyDict)
    #json.loads turns the json response into a dictionary
    data = json.loads(r.text)
    return data['access_token']



def listApplications():
    results = []
    listapp_url = "https://api.ams.fortify.com/api/v3/applications/"
    headers = {"Accept": "application/json", "Authorization": headerValue}
    params = {"fields": "applicationID,applicationName"}

    r = requests.get(listapp_url, headers=headers, data=params, proxies=proxyDict)
    data = json.loads(r.text)
    for app in data['items']:
        a = appinfo(app['applicationName'], app['applicationId'])
        results.append(a)
    return results

#Returns a String of the latest ReleaseID for the given appID
def getReleaseIDLatest(appID):
    releaseID = 0
    getRelease_url = "https://api.ams.fortify.com/api/v3/applications/{appID}/releases".format(appID=appID)
    headers = {"Accept": "application/json", "Authorization": headerValue}
    #params = {"filters": "applicationId:"+ str(appID)}

    r = requests.get(getRelease_url, headers=headers, proxies=proxyDict)
    data = json.loads(r.text)
    for release in data['items']:
        if release['releaseId'] > releaseID:
            releaseID = release['releaseId']
    return releaseID

def getReleaseDetails(releaseId):
    getRelease_url = "https://api.ams.fortify.com/api/v3/releases/{releaseId}".format(releaseId=releaseId)
    headers = {"Content-Type": "application/x-www-form-urlencoded", "Authorization": headerValue}
    #params = {"filters": "applicationId:"+ str(appID)}

    r = requests.get(getRelease_url, headers=headers, proxies=proxyDict)
    data = json.loads(r.text)
    return data

#Attempts to retire a specified release returning a dictionary with the following keys:
  # "success": true,
  # "errors": ["string"]
def retireRelease(releaseId):
    releaseDetails = getReleaseDetails(releaseId)
    headers = {"Content-Type": "application/json", "Authorization": headerValue}
    params = {"releaseName": releaseDetails['releaseName'], "releaseDescription": releaseDetails['releaseDescription'], "sdlcStatusType": "Retired", "ownerId": "11578"}
    retireRelease_url = "https://api.ams.fortify.com/api/v3/releases/{releaseId}".format(releaseId=releaseId)

    r = requests.put(retireRelease_url, headers=headers, json=params, proxies=proxyDict)
    data = json.loads(r.text)
    return data


#Creates a new release and returns a dictionary of the JSON results (releaseId, success[boolean], errors[array])
def createRelease(appID, releaseName, latestReleaseID):
    headers = {"Content-Type": "application/x-www-form-urlencoded", "Authorization": headerValue}
    params = {"applicationID": appID, "releaseName": releaseName, "releaseDescription": releaseName, "copyState": "True", "copyStateReleaseID": latestReleaseID, "sdlcStatusType": "Production"}
    createRelease_url = "https://api.ams.fortify.com/api/v3/releases"

    r = requests.post(createRelease_url, headers=headers, data=params, proxies=proxyDict)
    data = json.loads(r.text)
    return data

#Create Dynamic Scan for a specific ReleaseId, startDate pattern is MM/dd/yyyy HH:mm
def createDynamicScan(startDate, releaseId):
    headers = {"Content-Type": "application/json", "Authorization": headerValue}
    params = {"startDate": startDate, "assessmentTypeID": int(139), "entitlementId": int(4948), "entitlementFrequencyType": "Subscription", "isRemediationScan": "false", "isBundledAssessment": "false", "parentAssessmentTypeId": int(0)}
    createscan_url = "https://api.ams.fortify.com/api/v3/releases/{releaseId}/dynamic-scans/start-scan".format(releaseId=releaseId)

    r = requests.post(createscan_url, headers=headers, json=params, proxies=proxyDict)
    data = json.loads(r.text)
    return data

def getLastScanDate(appID):
    latestReleaseID = getReleaseIDLatest(appID)
    releaseDetails = getReleaseDetails(latestReleaseID)
    scanDate = releaseDetails['dynamicScanDate']
    releaseName = releaseDetails['releaseName']
    return latestReleaseID, scanDate, releaseName



def refreshApps():
    applist = []
    r = listApplications()
    f = open('currentScanDates.csv', 'w', newline='')
    writer = csv.writer(f, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)

    for a in r:
        releaseID, date, releaseName = getLastScanDate(a.appID)
        a.addinfo(releaseID, date, releaseName)
        applist.append(a)

    applist.sort(key=lambda x: x.lastRelease, reverse=False)

    t = PrettyTable(['Application Name', 'App ID', 'Release Name', 'Last Release ID', 'Last Scan Date'])
    writer.writerow(['Application Name', 'App ID', 'Release Name', 'Last Release ID', 'Last Scan Date'])

    for app in applist:
        t.add_row([str(app.appName), str(app.appID), str(app.releaseName), str(app.lastRelease), str(app.lastScan)])
        writer.writerow([str(app.appName), str(app.appID), str(app.releaseName), str(app.lastRelease), str(app.lastScan)])


    print(t)
    f.close()

def printApps():
    with open('currentScanDates.csv', "r") as f:
        t = from_csv(f)
    print(t)

def fridaySchedule(appID):    
    d = datetime.date.today()
    #finding the date of next Friday
    while d.weekday() != 4:
        d += datetime.timedelta(1)
    releaseName = d.strftime("%Y-%m-%d")
    startTime = d.strftime("%m/%d/%Y 20:00")

    lastReleaseID = getReleaseIDLatest(int(appID))
    createResult = createRelease(int(appID), str(releaseName), lastReleaseID)
    if createResult['success']:
        print("Release Creation Successful, Attempting to Retire existing Release")
        time.sleep(35)
        retireResult = retireRelease(lastReleaseID)
        if retireResult['success']:
            print("Release Retirement Successful, Attempting to schedule new scan")
            time.sleep(35)
            createScanResult = createDynamicScan(startTime, createResult['releaseId'])
            print(createScanResult['scanId'])

def scheduleScan(appID, newReleaseName):
    d = datetime.date.today()
    startTime = d.strftime("%m/%d/%Y %H:%M")
    lastReleaseID = getReleaseIDLatest(int(appID))
    createResult = createRelease(int(appID), str(newReleaseName), lastReleaseID)
    if createResult['success']:
        print("Release Creation Successful, Attempting to Retire existing Release")
        time.sleep(35)
        retireResult = retireRelease(lastReleaseID)
        if retireResult['success']:
            print("Release Retirement Successful, Attempting to schedule new scan")
            time.sleep(35)
            createScanResult = createDynamicScan(startTime, createResult['releaseId'])
            print(createScanResult)

def scheduleMulti(appIDs, newReleaseName):
    d = datetime.date.today()
    startTime = d.strftime("%m/%d/%Y %H:%M")
    
    for appID in appIDs:
        lastReleaseID = getReleaseIDLatest(int(appID))
        createResult = createRelease(int(appID), str(newReleaseName), lastReleaseID)
        if createResult['success']:
            print("Release Creation Successful, Attempting to Retire existing Release")
            time.sleep(35)
            retireResult = retireRelease(lastReleaseID)
            if retireResult['success']:
                print("Release Retirement Successful, Attempting to schedule new scan")
                time.sleep(35)
                createScanResult = createDynamicScan(startTime, createResult['releaseId'])
                print(createScanResult)

def getVulnerabilities(appID):
    lastReleaseID = getReleaseIDLatest(int(appID))
    getVulns_url = "https://api.ams.fortify.com/api/v3/releases/{releaseId}/vulnerabilities".format(releaseId=lastReleaseID)
    headers = {"Accept": "application/json", "Authorization": headerValue}

    r = requests.get(getVulns_url, headers=headers, proxies=proxyDict)
    data = json.loads(r.text)
    return data

def getReleaseVulnerabilities(releaseID):
    getVulns_url = "https://api.ams.fortify.com/api/v3/releases/{releaseId}/vulnerabilities".format(releaseId=releaseID)
    headers = {"Accept": "application/json", "Authorization": headerValue}

    r = requests.get(getVulns_url, headers=headers, proxies=proxyDict)
    data = json.loads(r.text)
    return data

def ReportAllVulnerabilities():
    appIDlist = []
    releaseIDlist = []
    vulnlist = []

    f = open('AllVulns.csv', 'w', newline='')
    writer = csv.writer(f, delimiter='@', quotechar='"', quoting=csv.QUOTE_MINIMAL)

    writer.writerow(['Application Name','AppID','Release Name','ReleaseID','Scan Date','Severity', 'Kingdom', 'Category', 'CWE', 'Location'])

    listapp_url = "https://api.ams.fortify.com/api/v3/applications/"    
    headers = {"Accept": "application/json", "Authorization": headerValue}
    params = {"fields": "applicationID,applicationName"}

    r = requests.get(listapp_url, headers=headers, data=params, proxies=proxyDict)
    data = json.loads(r.text)
    for app in data['items']:
        appIDlist.append([app['applicationId'], app['applicationName']])
        listrelease_url = "https://api.ams.fortify.com/api/v3/applications/{applicationId}/releases".format(applicationId=app['applicationId'])
        q = requests.get(listrelease_url, headers=headers, proxies=proxyDict)
        data2 = json.loads(q.text)
        for release in data2['items']:
            releaseIDlist.append([release['releaseId'], release['releaseName'], release['dynamicScanDate']])
            data3 = getReleaseVulnerabilities(release['releaseId'])
            for vuln in data3['items']:
                writer.writerow([app['applicationName'], app['applicationId'], release['releaseName'], release['releaseId'], release['dynamicScanDate'], vuln['severityString'], vuln['kingdom'], vuln['category'], vuln['cwe'], vuln['primaryLocation']])


def getVulnHistory(releaseID, vulnID):
    getVulnsHist_url = "https://api.ams.fortify.com/api/v3/releases/{releaseID}/vulnerabilities/{vulnID}/history".format(releaseID=lastReleaseID,vulnID=vulnID)
    headers = {"Accept": "application/json", "Authorization": headerValue}

    r = requests.get(getVulnsHist_url, headers=headers, proxies=proxyDict)
    data = json.loads(r.text)
    return data

def printVulnerabilities(appID):
    vulnlist = []
    data = getVulnerabilities(appID)
    for vuln in data['items']:
        v = vulninfo(vuln['severityString'], vuln['kingdom'], vuln['category'], vuln['cwe'], vuln['primaryLocation'])
        vulnlist.append(v)
    t = PrettyTable(['Severity', 'Kingdom', 'Category', 'CWE', 'Location'])

    vulnlist.sort(key=lambda x: x.sevCode, reverse=False)

    for v in vulnlist:
        t.add_row([str(v.severity), str(v.kingdom), str(v.category), str(v.cwe), str(v.location)])

    print(t)

def listAllVulns():
    appIDlist = []
    vulnlist = []

    f = open('allVulns.csv', 'w', newline='')
    writer = csv.writer(f, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)

    t = PrettyTable(['Application Name','Severity', 'Kingdom', 'Category', 'CWE', 'Location'])
    writer.writerow(['Application Name','Severity', 'Kingdom', 'Category', 'CWE', 'Location'])

    listapp_url = "https://api.ams.fortify.com/api/v3/applications/"
    headers = {"Accept": "application/json", "Authorization": headerValue}
    params = {"fields": "applicationID,applicationName"}

    r = requests.get(listapp_url, headers=headers, data=params, proxies=proxyDict)
    data = json.loads(r.text)
    for app in data['items']:
        appIDlist.append([app['applicationId'], app['applicationName']])

    for app in appIDlist:
        data2 = getVulnerabilities(app[0])
        appName = app[1]
        for vuln in data2['items']:
              v = vulninfo(vuln['severityString'], vuln['kingdom'], vuln['category'], vuln['cwe'], vuln['primaryLocation'])
              v.addinfo(appName)
              vulnlist.append(v)

        vulnlist.sort(key=lambda x: x.sevCode, reverse=False)

    for v in vulnlist:
        t.add_row([str(v.appName), str(v.severity), str(v.kingdom), str(v.category), str(v.cwe), str(v.location)])
        writer.writerow([str(v.appName), str(v.severity), str(v.kingdom), str(v.category), str(v.cwe), str(v.location)])

    print(t)

def listCurrentVulns():
    appIDlist = []
    vulnlist = []

    f = open('currentVulns.csv', 'w', newline='')
    writer = csv.writer(f, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)

    t = PrettyTable(['Application Name','Severity', 'Kingdom', 'Category', 'CWE', 'Location'])
    writer.writerow(['Application Name','Severity', 'Kingdom', 'Category', 'CWE', 'Location'])

    listapp_url = "https://api.ams.fortify.com/api/v3/applications/"
    headers = {"Accept": "application/json", "Authorization": headerValue}
    params = {"fields": "applicationID,applicationName"}

    r = requests.get(listapp_url, headers=headers, data=params, proxies=proxyDict)
    data = json.loads(r.text)
    for app in data['items']:
        appIDlist.append([app['applicationId'], app['applicationName']])

    for app in appIDlist:
        latestReleaseID = getReleaseIDLatest(app[0])
        appName = app[1]
        data2 = getReleaseVulnerabilities(latestReleaseID)
        for vuln in data2['items']:
              v = vulninfo(vuln['severityString'], vuln['kingdom'], vuln['category'], vuln['cwe'], vuln['primaryLocation'], vuln['scanCompletedDate'])
              v.addinfo(appName)
              vulnlist.append(v)

        vulnlist.sort(key=lambda x: x.sevCode, reverse=False)

    for v in vulnlist:
        t.add_row([str(v.appName), str(v.severity), str(v.kingdom), str(v.category), str(v.cwe), str(v.location)])
        writer.writerow([str(v.appName), str(v.severity), str(v.kingdom), str(v.category), str(v.cwe), str(v.location), str(v.scanDate)])

    print(t)

def scheduleList():
    list = list2
    name1 = '2017-01-26'
    scheduleMulti(list, name1)

list1 = [67006, 6294, 3840, 71498, 6042, 5576, 71497, 13084, 21854, 3844, 73385, 81071, 81233, 88525] 
list2 = [66483, 84928, 72658, 14283, 70020, 9128, 11233, 11232, 14473, 72814, 68011, 85459, 85842]
list3 = [67887, 67853, 3839, 67007, 4531, 4696, 3843, 83203, 12491, 75564, 9746, 9750, 85845]
list_temp = [66483, 72658, 14283, 70020, 9128, 11233, 11232, 14473, 72814, 68011, 85459, 85842]

def main():
    if cfg.use_Proxy:
        proxyDict = cfg.proxyDict
    #Global authToken call
    headerValue = "Bearer " + getToken()


if __name__ == '__main__':
    main()