import amsfodconfig as cfg
from prettytable import PrettyTable, from_csv
import csv
from fod_requests import fodRequest

#********************************Application Monitoring**********************************************************

def getAppMonConfig(AppID):
    """Get an Application Monitoring Configuration for a given application

    Args:
        AppID (str): This is the application ID of the Web App you are interested in.

    Returns:
        dict: Dictionary with three keys, enabled, scanUrl, and lastCompletedDate

    {
        "enabled": false,
        "scanUrl": null,
        "lastCompletedDate": null
    }

    """
    url = "https://api.ams.fortify.com/api/v3/applications/{appID}/application-monitoring/configuration".format(appID=AppID)
    req = fodRequest()
    r = req.get(url)
    return r
    
def getAppMonVulns(AppID, filters=None, orderBy=None, orderByDirection=None, fields=None, offset=None, limit=None):
    """Get Vulnerabilties found by Application Monitoring for a given application

    Args:
        AppID (str): This is the application ID of the Web App you are interested in.
        filters (str) *OPTIONAL*: A delimited list of field filters. Field name and value 
            should be separated by a colon (:). Multiple fields should be separated by a plus (+). 
            Multiple fields are treated as an AND condition. Example, fieldname1:value+fieldname2:value 
            Multiple values for a field should be separated by a pipe (|). Mulitple values for a 
            field are treated as an OR condition. Example, fieldname1:value1|value2
        orderBy (str) *OPTIONAL*: The field name to order the results by.
        orderByDirection (str) *OPTIONAL*: The direction to order the results by. ASC and DESC are valid values.
        fields (str) *OPTIONAL*: Comma separated list of fields to return.
        offset (str) *OPTIONAL*: Offset of the starting record. 0 indicates the first record.
        limit (str) *OPTIONAL*: Maximum records to return. The maximum value allowed is 50

    Returns:
        dict: Dictionary of dictionaries with the following layout

    {
    "items": [
    {
      "findingId": 0,
      "severityId": 0,
      "severity": "string",
      "categoryName": "string",
      "location": "string",
      "suppressed": true,
      "statusId": 0,
      "status": "string"
    }
        ],
    "totalCount": 0
    }

    """
    url = "https://api.ams.fortify.com/api/v3/applications/{appID}/application-monitoring/vulnerabilities".format(appID=AppID)
    if filters != None:
        if url.endswith('/vulnerabilities'):
            url = url + "?filters=" + str(filters)
        else:
            url = url + "&filters=" + str(filters)
    if orderBy !=None:
        if url.endswith('/vulnerabilities'):
            url = url + "?orderBy=" + str(orderBy)
        else:
            url = url + "&orderBy=" + str(orderBy)
    if orderByDirection !=None:
        if url.endswith('/vulnerabilities'):
            url = url + "?orderByDirection=" + str(orderByDirection)
        else:
            url = url + "&orderByDirection=" + str(orderByDirection)
    if fields != None:
        if url.endswith('/vulnerabilities'):
            url = url + "?fields=" + str(fields)
        else:
            url = url + "&fields=" + str(fields)
    if offset !=None:
        if url.endswith('/vulnerabilities'):
            url = url + "?offset=" + str(offset)
        else:
            url = url + "&offset=" + str(offset)
    if limit !=None:
        if url.endswith('/vulnerabilities'):
            url = url + "?limit=" + str(limit)
        else:
            url = url + "&limit=" + str(limit)

    req = fodRequest()
    r = req.get(url)
    return r