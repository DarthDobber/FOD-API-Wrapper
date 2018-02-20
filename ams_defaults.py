import amsfodconfig as cfg
from prettytable import PrettyTable, from_csv
import csv
from fod_requests import fodRequest
import helpers

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
        offset (integer) *OPTIONAL*: Offset of the starting record. 0 indicates the first record.
        limit (integer) *OPTIONAL*: Maximum records to return. The maximum value allowed is 50

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
    endsWith = url[-7:]
    new_url = helpers.urlEditor(url, endsWith, filters, orderBy, orderByDirection, fields, offset, limit)

    req = fodRequest()
    r = req.get(new_url)
    return r

def getAppMonRiskProfiles(AppID, filters=None, orderBy=None, orderByDirection=None, fields=None, offset=None, limit=None):
    """Get all Application Monitoring Risk Profiles for a given Application

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
        offset (integer) *OPTIONAL*: Offset of the starting record. 0 indicates the first record.
        limit (integer) *OPTIONAL*: Maximum records to return. The maximum value allowed is 50

    Returns:
        dict: Dictionary of dictionaries with the following layout

    {
    "items": [
        {
        "findingId": 0,
        "categoryName": "string",
        "findingName": "string",
        "statusId": 0,
        "status": "string"
        }
    ],
    "totalCount": 0
    }
    """
    url = "https://api.ams.fortify.com/api/v3/applications/{applicationId}/application-monitoring/risk-profiles".format(applicationId=AppID)
    endsWith = url[-7:]
    new_url = helpers.urlEditor(url, endsWith, filters, orderBy, orderByDirection, fields, offset, limit)

    req = fodRequest()
    r = req.get(new_url)
    return r

def updateAppMonConf(AppID, requestModel):
    """Update an Application Monitoring Configuration for a given application

    Args:
        AppID (str): This is the application ID of the Web App you are interested in.
        requestModel: This is the data you wish to update and you need to put it in this
            format:
                    {
                        "enabled": true,
                        "scanUrl": "https://mywebapp.com/directory"
                    }
            explanation:
                    {
                        enabled (boolean): Enable Application Monitoring ,
                        scanUrl (string): Scan Url
                    }

    Returns:
        dict: Dictionary with the following layout

        {
            "success": true,
            "errors": [
                "string"
            ]
        }

        In the case of a return code 204, the update will take place but you will not 
        get the above layout, instead you will get a custom layout like this:

        {'Response_Text': u'', 'Status_code': 204}
    """
    url = "https://api.ams.fortify.com/api/v3/applications/{applicationId}/application-monitoring/configuration".format(applicationId=AppID)

    req = fodRequest()
    r = req.put(url, params=requestModel)
    return r

    #*******************************************************Applications**************************************************************

    