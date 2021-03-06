def urlEditor(AppID, endsWith, filters, orderBy, orderByDirection, fields, offset, limit):
    """Edits the URL to include any optional parameter

    Args:
        AppID (str): This is the application ID of the Web App you are interested in.
        endsWith (str): The end of the original URL so that the function can determine what the 
            first parameter will be.
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
        url (str): URL with any added parameters
    """
    if filters != None:
        if url.endswith(str(endsWith)):
            url = url + "?filters=" + str(filters)
        else:
            url = url + "&filters=" + str(filters)
    if orderBy !=None:
        if url.endswith(str(endsWith)):
            url = url + "?orderBy=" + str(orderBy)
        else:
            url = url + "&orderBy=" + str(orderBy)
    if orderByDirection !=None:
        if url.endswith(str(endsWith)):
            url = url + "?orderByDirection=" + str(orderByDirection)
        else:
            url = url + "&orderByDirection=" + str(orderByDirection)
    if fields != None:
        if url.endswith(str(endsWith)):
            url = url + "?fields=" + str(fields)
        else:
            url = url + "&fields=" + str(fields)
    if offset !=None:
        if url.endswith(str(endsWith)):
            url = url + "?offset=" + str(offset)
        else:
            url = url + "&offset=" + str(offset)
    if limit !=None:
        if url.endswith(str(endsWith)):
            url = url + "?limit=" + str(limit)
        else:
            url = url + "&limit=" + str(limit)
    return url