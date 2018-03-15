# Logging example

The purpose of this is to demonstrate setting up CloudTrail to write to an S3 bucket, with server-side encryption in play.
It also sets up the rudiments of VPC FLow logging, but does _not_ yet include writing those logs out to S3 (there are complexities around
  using S3 server-side-encryption that need to be able to sort out.)

The scripts set up a VPC containing a subnet and an EC2 instance, so that you can SSH to it and generate some Flow Logs recording the traffic.

## Usage
It is assumed that:
 - the AWS CLI is available
 - appropriate AWS credentials are available
 - terraform is available
 - the scripts are being run on a unix account.

Start by making an `env.rc` file using the `env.rc.template` - this is used by the `bootstrap.sh` script to create and install an SSH KeyPair.
Next make a `terraform.tfvars` file using the `terraform.tfvars.template`, and finally

```
terraform init
terraform apply
```

After a bit of grinding, you should see output similar to

```
Apply complete! Resources: 0 added, 3 changed, 0 destroyed.

Outputs:

connect_string = ssh -i log-example.pem ec2-user@ec2-35-178-15-241.eu-west-2.compute.amazonaws.com
encryption_key_arn = arn:aws:kms:eu-west-2:889199313043:key/c78f8454-93de-428a-9fbd-6600fbb570f1
log_bucket_arn = arn:aws:s3:::example-logs20180305121401385000000001
private_dns = ip-172-24-0-23.eu-west-2.compute.internal
public_dns = ec2-35-178-15-241.eu-west-2.compute.amazonaws.com
trail_arn = arn:aws:cloudtrail:eu-west-2:889199313043:trail/example-trail
```

## Encryption
You will notice in the example that we are hard-wiring use of the KMS key to allow decryption of the logs (and hence reading them via the console)
to a particular IAM user. There are complexities around privileges for reading these encrypted logs, and discussion is somewhat out of scope here
as it will depend exactly on what you want to do with them.

## CloudTrail Validation
Fortunately the AWS CLI tool for testing the validity of the logs does not need to decrypt the logs (although it does require permissions to describe the CloudTrail trail, and to use the S3 bucket). Please see https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-cli.html for more information on this tool.

There is value in periodically testing the validity of the logs, and this could easily be automated by using an invocation similar to:

```
aws --profile adm_rhook_cli --region eu-west-2 cloudtrail validate-logs --trail-arn arn:aws:cloudtrail:eu-west-2:889199313043:trail/example-trail --start-time 2015-03-6T00:00:00Z
```

which would give a report similar to:

```
Validating log files for trail arn:aws:cloudtrail:eu-west-2:889199313043:trail/example-trail between 2015-03-06T00:00:00Z and 2018-03-08T19:34:33Z

Results requested for 2015-03-06T00:00:00Z to 2018-03-08T19:34:33Z
Results found for 2018-03-05T12:50:37Z to 2018-03-08T18:50:37Z:

78/78 digest files valid
691/691 log files valid
```

## CloudWatch Alerts
A handful of examples of using the CloudTrail logs to drive CloudWatch alerts can be found in the `cloudtrail.tf` file. These are all actions
which are of particular security interest, and are shown in this example as using [SNS](https://aws.amazon.com/sns/) to send messages to [SQS](https://aws.amazon.com/sqs/) for some arbitrary downstream consumer. Please note that the security around SNS and SQS in this example is only sketched out, as it's not the focus of this example.

## License
Copyright 2018 Leap Beyond Analytics

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
