import boto3
import logging
import json
import gzip
import urllib
import time
import os
from StringIO import StringIO
from botocore.client import Config

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3 = boto3.client('s3', config=Config(signature_version='s3v4'))

def lambda_handler(event, context):
    bucketS3 = os.environ['bucketS3']
    folderS3 = os.environ['folderS3']
    prefixS3 = os.environ['prefixS3']

    #capture the CloudWatch log data
    outEvent = str(event['awslogs']['data'])
    outEvent = gzip.GzipFile(fileobj=StringIO(outEvent.decode('base64','strict'))).read()

    cleanEvent = json.loads(outEvent)

    tempFile = open('/tmp/file', 'w+')
    for t in cleanEvent['logEvents']:
        tempFile.write(str(t) + "\n");
    tempFile.close()

    key = folderS3 + '/' + prefixS3 + str(int(time.time())) + ".log"
    s3Results = s3.upload_file(
            '/tmp/file',
            bucketS3,
            key,
            ExtraArgs={"ServerSideEncryption": "aws:kms"}
        )
    logger.info(bucketS3 + '/' + key + " uploaded")
    print s3Results
