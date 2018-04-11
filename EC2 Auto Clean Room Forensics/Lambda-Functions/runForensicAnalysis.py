# MIT No Attribution

# Permission is hereby granted, free of charge, to any person obtaining a copy of this
# software and associated documentation files (the "Software"), to deal in the Software
# without restriction, including without limitation the rights to use, copy, modify,
# merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
# PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import boto3

ssmclient = boto3.client('ssm')

def lambda_handler(event, context):
    
    # Sample Command - commands = ['sudo mkdir /forensics','sudo dd if=/dev/sda2 of=/forensics/i-23sdf5esdf.dd' ,'fls -r -m -i /forensics/i-23sdf5esdf.dd >/home/ubuntu/file-full-i-23sdf5esdf.txt', 'fls -rd /forensics/i-23sdf5esdf.dd']instance-forensics-syd-469306637372-dy2kenr1
    instanceID = event['instanceID']
    # Sample Command -  commands = ['#!/bin/bash','printf -v date "%(%F)T" -1', 'sudo mkdir /forensics','dd if=/dev/xvdb1 of=/forensics/i-23sdf5esdf.dd' ,'fls -r -m -i /forensics/i-23sdf5esdf.dd >/home/ubuntu/file-full-i-23sdf5esdf.txt', 'mactime -b /home/ubuntu/file-full-i-23sdf5esdf.txt $date >/home/ubuntu/file-2018-i-23sdf5esdf.txt', 'fls -rd /forensics/i-23sdf5esdf.dd', 'sudo apt-get install cloud-utils ','EC2_INSTANCE_ID=$(ec2metadata --instance-id)', 'cp /home/ubuntu/file-2018-i-23sdf5esdf.txt /home/ubuntu/$EC2_INSTANCE_ID.txt', 'cp /home/ubuntu/file-full-i-23sdf5esdf.txt file-full-$EC2_INSTANCE_ID.txt', 'aws s3 cp file-full-$EC2_INSTANCE_ID.txt s3://sydney-summit-incident-response/incident-response/file-full-$EC2_INSTANCE_ID.txt', 'aws s3 cp $EC2_INSTANCE_ID.txt s3://sydney-summit-incident-response/incident-response/$EC2_INSTANCE_ID.txt']
    commands = ['#!/bin/bash','printf -v date "%(%F)T" -1', 'sudo mkdir /forensics','dd if=/dev/xvdb1 of=/forensics/i-23sdf5esdf.dd' ,'fls -r -m -i /forensics/i-23sdf5esdf.dd >/home/ubuntu/file-full-i-23sdf5esdf.txt', 'mactime -b /home/ubuntu/file-full-i-23sdf5esdf.txt $date >/home/ubuntu/file-2018-i-23sdf5esdf.txt', 'fls -rd /forensics/i-23sdf5esdf.dd >/home/ubuntu/file-deleted-i-23sdf5esdf.txt', 'sudo apt-get install cloud-utils ','EC2_INSTANCE_ID=$(ec2metadata --instance-id)', 'cp /home/ubuntu/file-deleted-i-23sdf5esdf.txt /home/ubuntu/file-deleted-$EC2_INSTANCE_ID-' + instanceID+ '.txt', 'cp /home/ubuntu/file-2018-i-23sdf5esdf.txt /home/ubuntu/$EC2_INSTANCE_ID.txt', 'cp /home/ubuntu/file-full-i-23sdf5esdf.txt /home/ubuntu/file-full-$EC2_INSTANCE_ID.txt', 'aws s3 cp /home/ubuntu/file-full-$EC2_INSTANCE_ID.txt s3://instance-forensics-syd-469306637372-dy2kenr1/incident-response/file-full-$EC2_INSTANCE_ID.txt','aws s3 cp /home/ubuntu/file-deleted-$EC2_INSTANCE_ID-' + instanceID+ '.txt s3://instance-forensics-syd-469306637372-dy2kenr1/incident-response/file-deleted-$EC2_INSTANCE_ID-' + instanceID+ '.txt', 'aws s3 cp /home/ubuntu/$EC2_INSTANCE_ID.txt s3://instance-forensics-syd-469306637372-dy2kenr1/incident-response/$EC2_INSTANCE_ID.txt']
    # Sample Command -  commands = ['#!/bin/bash','printf -v date "%(%F)T" -1', 'sudo mkdir /forensics','dd if=/dev/xvdb1 of=/forensics/i-23sdf5esdf.dd' ,'fls -r -m -i /forensics/i-23sdf5esdf.dd >/home/ubuntu/file-full-i-23sdf5esdf.txt', 'mactime -b /home/ubuntu/file-full-i-23sdf5esdf.txt $date >/home/ubuntu/file-2018-i-23sdf5esdf.txt', 'fls -rd /forensics/i-23sdf5esdf.dd', 'sudo apt-get install cloud-utils ','EC2_INSTANCE_ID=$(ec2metadata --instance-id)', 'cp /home/ubuntu/file-2018-i-23sdf5esdf.txt /home/ubuntu/$EC2_INSTANCE_ID.txt', 'cp /home/ubuntu/file-full-i-23sdf5esdf.txt /home/ubuntu/file-full-$EC2_INSTANCE_ID.txt', 'aws s3 cp /home/ubuntu/file-full-$EC2_INSTANCE_ID.txt s3://instance-forensics-syd-469306637372-dy2kenr1/incident-response/file-full-$EC2_INSTANCE_ID.txt', 'aws s3 cp /home/ubuntu/$EC2_INSTANCE_ID.txt s3://instance-forensics-syd-469306637372-dy2kenr1/incident-response/$EC2_INSTANCE_ID.txt']
    # Sample Command -  commands = ['#!/bin/bash','printf -v date "%(%F)T" -1', 'sudo mkdir /forensics','dd if=/dev/xvdb1 of=/forensics/i-23sdf5esdf.dd' ,'fls -r -m -i /forensics/i-23sdf5esdf.dd >/home/ubuntu/file-full-i-23sdf5esdf.txt', 'mactime -b /home/ubuntu/file-full-i-23sdf5esdf.txt $date >/home/ubuntu/file-2018-i-23sdf5esdf.txt', 'fls -rd /forensics/i-23sdf5esdf.dd', 'sudo apt-get install cloud-utils ','EC2_INSTANCE_ID=$(ec2metadata --instance-id)', 'cp /home/ubuntu/file-2018-i-23sdf5esdf.txt /home/ubuntu/$EC2_INSTANCE_ID.txt', 'cp /home/ubuntu/file-full-i-23sdf5esdf.txt file-full-$EC2_INSTANCE_ID.txt', 'aws s3 cp file-full-$EC2_INSTANCE_ID.txt s3://sydney-summit-incident-response/incident-response/file-full-$EC2_INSTANCE_ID.txt', 'aws s3 cp $EC2_INSTANCE_ID.txt s3://sydney-summit-incident-response/incident-response/$EC2_INSTANCE_ID.txt']
    response = ssmclient.send_command(
            InstanceIds= [event.get('ForensicInstanceId')],
            DocumentName='AWS-RunShellScript',
            Parameters={
            'commands': commands,
            'executionTimeout': ['600'] # Seconds all commands have to complete in
            },
            Comment='SSM Command Execution',
            # sydney-summit-incident-response
            OutputS3Region='ap-southeast-2',
            OutputS3BucketName='sydney-summit-incident-response',
            OutputS3KeyPrefix=event.get('ForensicInstanceId')
            # ,
            # ServiceRoleArn='arn:aws:iam::469306637372:role/SNSServiceRole',
            # NotificationConfig={
            #     'NotificationArn': 'arn:aws:sns:ap-southeast-2:469306637372:SecurityAlertMessages',
            #     'NotificationEvents': [
            #         'All',
            #     ],
            #     'NotificationType': 'Command'
            # }
        )
    print (response)
    return event
