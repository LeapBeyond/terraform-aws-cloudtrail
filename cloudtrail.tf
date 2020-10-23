# -----------------------------------------------------------
# setup permissions to allow cloudtrail to write to cloudwatch
# -----------------------------------------------------------
resource "aws_iam_role" "cloudtrail_example" {
  name = "cloudtrail-to-cloudwatch"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "cloudtrail.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "cloudtrail_example" {
  name = "cloudtrail-example"
  role = "${aws_iam_role.cloudtrail_example.id}"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AWSCloudTrailCreateLogStream",
      "Effect": "Allow",
      "Action": ["logs:CreateLogStream"],
      "Resource": [
        "arn:aws:logs:${var.aws_region}:${var.aws_account_id}:log-group:${aws_cloudwatch_log_group.cloudtrail.id}:log-stream:*"
      ]
    },
    {
      "Sid": "AWSCloudTrailPutLogEvents",
      "Effect": "Allow",
      "Action": ["logs:PutLogEvents"],
      "Resource": [
        "arn:aws:logs:${var.aws_region}:${var.aws_account_id}:log-group:${aws_cloudwatch_log_group.cloudtrail.id}:log-stream:*"
      ]
    }
  ]
}
EOF
}

# -----------------------------------------------------------
# setup cloudwatch logs to receive cloudtrail events
# -----------------------------------------------------------

resource "aws_cloudwatch_log_group" "cloudtrail" {
  name = "cloudtrail"

  kms_key_id        = "${aws_kms_key.cloudtrail_key.arn}"
  retention_in_days = 30
  tags              = "${merge(map("Name", "Cloudtrail"), var.tags)}"
}

# -----------------------------------------------------------
# turn cloudtrail on for this region
# -----------------------------------------------------------

resource "aws_cloudtrail" "example" {
  name                          = "${var.trail_name}"
  s3_bucket_name                = "${aws_s3_bucket.log_bucket.id}"
  s3_key_prefix                 = "${var.trail_name}"
  include_global_service_events = true
  enable_logging                = true
  is_multi_region_trail         = false
  enable_log_file_validation    = true
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.cloudtrail.arn}"
  cloud_watch_logs_role_arn     = "${aws_iam_role.cloudtrail_example.arn}"
  kms_key_id                    = "${aws_kms_key.cloudtrail_key.arn}"

  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }

  tags = "${merge(map("Name", "Example account audit"), var.tags)}"
}

# -----------------------------------------------------------
# setup audit filters
# -----------------------------------------------------------

# ----------------------
# watch for use of the root account
# ----------------------
resource "aws_cloudwatch_log_metric_filter" "root_login" {
  name           = "root-access"
  pattern        = "{$.userIdentity.type = Root}"
  log_group_name = "${aws_cloudwatch_log_group.cloudtrail.name}"

  metric_transformation {
    name      = "RootAccessCount"
    namespace = "${var.metric_name_space}"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "root_login" {
  alarm_name          = "root-access-${var.aws_region}"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "RootAccessCount"
  namespace           = "${var.metric_name_space}"
  period              = "60"
  statistic           = "Sum"
  threshold           = "1"
  alarm_description   = "Use of the root account has been detected"
  alarm_actions       = ["${aws_sns_topic.security_alerts.arn}"]
}

# ----------------------
# watch for use of the console without MFA
# ----------------------
resource "aws_cloudwatch_log_metric_filter" "console_without_mfa" {
  name           = "console-without-mfa"
  pattern        = "{$.eventName = ConsoleLogin && $.additionalEventData.MFAUsed = No}"
  log_group_name = "${aws_cloudwatch_log_group.cloudtrail.name}"

  metric_transformation {
    name      = "ConsoleWithoutMFACount"
    namespace = "${var.metric_name_space}"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "console_without_mfa" {
  alarm_name          = "console-without-mfa-${var.aws_region}"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "ConsoleWithoutMFACount"
  namespace           = "${var.metric_name_space}"
  period              = "60"
  statistic           = "Sum"
  threshold           = "1"
  alarm_description   = "Use of the console by an account without MFA has been detected"
  alarm_actions       = ["${aws_sns_topic.security_alerts.arn}"]
}

# ----------------------
# watch for actions triggered by accounts without MFA
# ----------------------
resource "aws_cloudwatch_log_metric_filter" "action_without_mfa" {
  name           = "action-without-mfa"
  pattern        = "{$.userIdentity.type != AssumedRole && $.userIdentity.sessionContext.attributes.mfaAuthenticated != true}"
  log_group_name = "${aws_cloudwatch_log_group.cloudtrail.name}"

  metric_transformation {
    name      = "UseWithoutMFACount"
    namespace = "${var.metric_name_space}"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "action_without_mfa" {
  alarm_name          = "action-without-mfa-${var.aws_region}"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "UseWithoutMFACount"
  namespace           = "${var.metric_name_space}"
  period              = "60"
  statistic           = "Sum"
  threshold           = "1"
  alarm_description   = "Actions triggered by a user account without MFA has been detected"
  alarm_actions       = ["${aws_sns_topic.security_alerts.arn}"]
}

# ----------------------
# look for key alias changes or key deletions
# ----------------------
resource "aws_cloudwatch_log_metric_filter" "illegal_key_use" {
  name           = "key-changes"
  pattern        = "{$.eventSource = kms.amazonaws.com && ($.eventName = DeleteAlias || $.eventName = DisableKey)}"
  log_group_name = "${aws_cloudwatch_log_group.cloudtrail.name}"

  metric_transformation {
    name      = "KeyChangeOrDelete"
    namespace = "${var.metric_name_space}"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "illegal_key_use" {
  alarm_name          = "key-changes-${var.aws_region}"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "KeyChangeOrDelete"
  namespace           = "${var.metric_name_space}"
  period              = "60"
  statistic           = "Sum"
  threshold           = "1"
  alarm_description   = "A key alias has been changed or a key has been deleted"
  alarm_actions       = ["${aws_sns_topic.security_alerts.arn}"]
}

# ----------------------
# look for use of KMS keys by users
# ----------------------
resource "aws_cloudwatch_log_metric_filter" "decription_with_key" {
  name           = "decription_with_key"
  pattern        = "{($.userIdentity.type = IAMUser || $.userIdentity.type = AssumeRole) && $.eventSource = kms.amazonaws.com && $.eventName = Decrypt}"
  log_group_name = "${aws_cloudwatch_log_group.cloudtrail.name}"

  metric_transformation {
    name      = "DecryptionWithKMS"
    namespace = "${var.metric_name_space}"
    value     = "1"
  }
}

# ----------------------
# look for changes to security groups
# ----------------------
resource "aws_cloudwatch_log_metric_filter" "security_group_change" {
  name           = "security-group-changes"
  pattern        = "{ $.eventName = AuthorizeSecurityGroup* || $.eventName = RevokeSecurityGroup* || $.eventName = CreateSecurityGroup || $.eventName = DeleteSecurityGroup }"
  log_group_name = "${aws_cloudwatch_log_group.cloudtrail.name}"

  metric_transformation {
    name      = "SecurityGroupChanges"
    namespace = "${var.metric_name_space}"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "security_group_change" {
  alarm_name          = "security-group-changes-${var.aws_region}"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "SecurityGroupChanges"
  namespace           = "${var.metric_name_space}"
  period              = "60"
  statistic           = "Sum"
  threshold           = "1"
  alarm_description   = "Security groups have been changed"
  alarm_actions       = ["${aws_sns_topic.security_alerts.arn}"]
}

# ----------------------
# look for changes to IAM resources
# ----------------------
resource "aws_cloudwatch_log_metric_filter" "iam_change" {
  name           = "iam-changes"
  pattern        = "{$.eventSource = iam.* && $.eventName != Get* && $.eventName != List*}"
  log_group_name = "${aws_cloudwatch_log_group.cloudtrail.name}"

  metric_transformation {
    name      = "IamChanges"
    namespace = "${var.metric_name_space}"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "iam_change" {
  alarm_name          = "iam-changes-${var.aws_region}"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "IamChanges"
  namespace           = "${var.metric_name_space}"
  period              = "60"
  statistic           = "Sum"
  threshold           = "1"
  alarm_description   = "IAM Resources have been changed"
  alarm_actions       = ["${aws_sns_topic.security_alerts.arn}"]
}

# ----------------------
# look for changes to route table resources
# ----------------------
resource "aws_cloudwatch_log_metric_filter" "routetable_change" {
  name           = "route-table-changes"
  pattern        = "{$.eventSource = ec2.* && ($.eventName = AssociateRouteTable || $.eventName = CreateRoute* || $.eventName = CreateVpnConnectionRoute || $.eventName = DeleteRoute* || $.eventName = DeleteVpnConnectionRoute || $.eventName = DisableVgwRoutePropagation || $.eventName = DisassociateRouteTable || $.eventName = EnableVgwRoutePropagation || $.eventName = ReplaceRoute*)}"
  log_group_name = "${aws_cloudwatch_log_group.cloudtrail.name}"

  metric_transformation {
    name      = "RouteTableChanges"
    namespace = "${var.metric_name_space}"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "routetable_change" {
  alarm_name          = "route-table-changes-${var.aws_region}"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "RouteTableChanges"
  namespace           = "${var.metric_name_space}"
  period              = "60"
  statistic           = "Sum"
  threshold           = "1"
  alarm_description   = "Route Table Resources have been changed"
  alarm_actions       = ["${aws_sns_topic.security_alerts.arn}"]
}

# ----------------------
# look for changes to NACL
# ----------------------
resource "aws_cloudwatch_log_metric_filter" "nacl_change" {
  name           = "nacl-changes"
  pattern        = "{$.eventSource = ec2.* && ($.eventName = CreateNetworkAcl* || $.eventName = DeleteNetworkAcl* || $.eventName = ReplaceNetworkAcl*)}"
  log_group_name = "${aws_cloudwatch_log_group.cloudtrail.name}"

  metric_transformation {
    name      = "NaclChanges"
    namespace = "${var.metric_name_space}"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "nacl_change" {
  alarm_name          = "nacl-changes-${var.aws_region}"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "NaclChanges"
  namespace           = "${var.metric_name_space}"
  period              = "60"
  statistic           = "Sum"
  threshold           = "1"
  alarm_description   = "NACL have been changed"
  alarm_actions       = ["${aws_sns_topic.security_alerts.arn}"]
}

#nacl

# -----------------------------------------------------------
# set up SNS for sending alerts out. note there is only rudimentary security on this
# -----------------------------------------------------------
resource "aws_sns_topic" "security_alerts" {
  name         = "security-alerts-topic"
  display_name = "Security Alerts"
}

resource "aws_sns_topic_subscription" "security_alerts_to_sqs" {
  topic_arn = "${aws_sns_topic.security_alerts.arn}"
  protocol  = "sqs"
  endpoint  = "${aws_sqs_queue.security_alerts.arn}"
}

resource "aws_sqs_queue" "security_alerts" {
  name = "security-alerts-${var.aws_region}"
  tags = "${merge(map("Name", "Security Alerts"), var.tags)}"
}

resource "aws_sqs_queue_policy" "sns_to_sqs" {
  queue_url = "${aws_sqs_queue.security_alerts.id}"

  policy = <<EOF
{
"Version":"2012-10-17",
"Statement":[
  {
    "Effect":"Allow",
    "Principal":"*",
    "Action":"sqs:SendMessage",
    "Resource":"${aws_sqs_queue.security_alerts.arn}",
    "Condition":{
      "ArnEquals":{
        "aws:SourceArn":"${aws_sns_topic.security_alerts.arn}"
      }
    }
  }
]
}
EOF
}
