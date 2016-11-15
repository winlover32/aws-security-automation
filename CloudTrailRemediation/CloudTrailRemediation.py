'''
Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance with the License. A copy of the License is located at
    http://aws.amazon.com/apache2.0/
or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
'''

import boto3

LOGTABLE = "cweCloudTrailLog"

def lambda_handler(event, context):

    # Extract user info from the event
    trailArn = event['detail']['requestParameters']['name']
    try:
        userName = event['detail']['userIdentity']['userName']
    except KeyError:
        # User is federated/assumeRole
        userName = event['detail']['userIdentity']['sessionContext']['sessionIssuer']['userName']
    userArn = event['detail']['userIdentity']['arn']
    accessKeyId = event['detail']['userIdentity']['accessKeyId']
    trailArn = event['detail']['requestParameters']['name']
    region = event['region']
    account = event['account']
    eventTime = event['detail']['eventTime']
    userAgent = event['detail']['userAgent']
    sourceIP = event['detail']['sourceIPAddress']
    logData = {}
    logData = {'trailArn' : trailArn, 'userName' : userName, 'userArn' : userArn, 'accessKeyId' : accessKeyId, 'region' : region, 'account' : account, 'eventTime' : eventTime, 'userAgent' : userAgent, 'sourceIP' : sourceIP}


    # Priority action
    startTrail(trailArn)

    # Alerting
    result = sendAlert(logData)

    # Forensics
    realTable = verifyLogTable()
    result = forensic(logData, realTable)

    # Logging
    result = logEvent(logData, realTable)
    return result


def verifyLogTable():
    # Find table
    client = boto3.client('dynamodb')
    response = client.list_tables()
    table = LOGTABLE
    for i in range(len(response['TableNames'])):
        if table in response['TableNames'][i]:
            table = response['TableNames'][i]
    return table


def startTrail(trailArn):
    client = boto3.client('cloudtrail')
    response = client.get_trail_status(
        Name=trailArn
    )
    # Check if someone already started the trail
    if response['IsLogging']:
        print "Logging already started"
        return "NoActionNeeded"
    else:
        print "Starting trail: ", trailArn
        response = client.start_logging(
            Name=trailArn
        )
        return "Trail started"


def sendAlert(data):
    # Placeholder for alert function.
    # This could be Amazon SNS, SMS, Email or adding to a ticket tracking system like Jira or Remedy.
    print "No alert"
    return 0


def forensic(data, table):
    # Placeholder for forensic.
    # Examples: Look for MFA, Look for previous violations, your corporate CIDR blocks etc.
    remediationStatus = True

    # Placeholder for forensic like has the user done this before etc
    # Set remediationStatus to True to trigger remediation function
    if remediationStatus: #If needed, disable users access keys
        # See if user have tried this before
        client = boto3.client('dynamodb')
        response = client.get_item(
            TableName=table,
            Key={
                'userName': {'S':data['userName']}
            }
        )
        try:
            if response['Item']:
                result = disableAccount(data['userName'])
                return result
        except:
            # First time incident
            return "NoRemediationNeeded"


def disableAccount(userName):
    print "No action added"
        # Deactivate AccessKey or add deny policy using iam
    client = boto3.client('iam')
    response = client.put_user_policy(
        UserName=userName,
        PolicyName='BlockPolicy',
        PolicyDocument={"Version":"2012-10-17", "Statement":{"Effect":"Deny", "Action":"*", "Resource":"*"}}
    )
    return 0


def logEvent(logData, table):
    client = boto3.client('dynamodb')
    resource = boto3.resource('dynamodb')

    # Name of the table to use
    response = client.list_tables()

    # Verify that the table exists
    tableExists = False
    try:
        result = client.describe_table(TableName=table)
        tableExists = True
    except:
        # Table does not exist, create it
        table = resource.create_table(
            TableName=table,
            KeySchema=[
                {'AttributeName': 'userName', 'KeyType': 'HASH'},
                {'AttributeName': 'eventTime', 'KeyType': 'RANGE'}
            ],
            AttributeDefinitions=[
                {'AttributeName': 'userName', 'AttributeType': 'S'},
                {'AttributeName': 'eventTime', 'AttributeType': 'S'}
            ],
            ProvisionedThroughput={'ReadCapacityUnits': 5, 'WriteCapacityUnits': 5}
        )

        # Wait for table creation
        table.meta.client.get_waiter('table_exists').wait(TableName=table)
        tableExists = True

    # Store data
    response = client.put_item(
        TableName=table,
        Item={
            'userName' : {'S': logData['userName']},
            'eventTime' : {'S': logData['eventTime']},
            'userArn' : {'S': logData['userArn']},
            'region' : {'S': logData['region']},
            'account' : {'S': logData['account']},
            'userAgent' : {'S': logData['userAgent']},
            'sourceIP' : {'S': logData['sourceIP']}
        }
    )
    return 0
