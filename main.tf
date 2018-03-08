provider "aws" {
  region  = "${var.aws_region}"
  profile = "${var.aws_profile}"
}

# -----------------------------------------------------------
# set up logging bucket keys
# -----------------------------------------------------------

resource "aws_kms_key" "log_key" {
  deletion_window_in_days = 7
  description             = "Log Bucket Encryption Key"
  enable_key_rotation     = true
  tags                    = "${merge(map("Name","Log Bucket Key"), var.tags)}"
}

resource "aws_kms_alias" "log_key" {
  name          = "alias/log_key"
  target_key_id = "${aws_kms_key.log_key.id}"
}

resource "aws_kms_key" "cloudtrail_key" {
  deletion_window_in_days = 7
  description             = "CloudTrail Log Encryption Key"
  enable_key_rotation     = true
  tags                    = "${merge(map("Name","CloudTrail Key"), var.tags)}"

  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Enable IAM User Permissions",
      "Effect": "Allow",
      "Principal": {
        "AWS": [
          "arn:aws:iam::${var.aws_account_id}:root"
        ]
      },
      "Action": "kms:*",
      "Resource": "*"
    },

    {
      "Sid": "Allow CloudTrail to encrypt logs",
      "Effect": "Allow",
      "Principal": {
        "Service": "cloudtrail.amazonaws.com"
      },
      "Action": "kms:GenerateDataKey*",
      "Resource": "*",
      "Condition": {
        "StringLike": {
          "kms:EncryptionContext:aws:cloudtrail:arn": [
            "arn:aws:cloudtrail:*:${var.aws_account_id}:trail/*"
          ]
        }
      }
    },

    {
      "Sid": "Enable CloudTrail log decrypt permissions",
      "Effect": "Allow",
      "Principal": {
        "AWS": [
          "arn:aws:iam::${var.aws_account_id}:user/${var.log_reader}"
        ]
      },
      "Action": ["kms:Decrypt"],
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "kms:CallerAccount" : "${var.aws_account_id}",
          "kms:ViaService": "s3.${var.aws_region}.amazonaws.com",
          "kms:EncryptionContext:aws:cloudtrail:arn": "arn:aws:cloudtrail:${var.aws_region}:${var.aws_account_id}:trail/${var.trail_name}"
        },
        "StringLike" : {
          "kms:EncryptionContext:aws:s3:arn":"${aws_s3_bucket.log_bucket.arn}/${var.trail_name}/AWSLogs/${var.aws_account_id}/CloudTrail/${var.aws_region}/*"
        }
      }
    },

    {
      "Sid": "Allow CloudTrail access",
      "Effect": "Allow",
      "Principal": {
        "Service": "cloudtrail.amazonaws.com"
      },
      "Action": "kms:DescribeKey",
      "Resource": "*"
    },

    {
      "Sid": "Allow CloudWatch Access",
      "Effect": "Allow",
      "Principal": {
        "Service": "logs.${var.aws_region}.amazonaws.com"
      },
      "Action": [
        "kms:Encrypt*",
        "kms:Decrypt*",
        "kms:ReEncrypt*",
        "kms:GenerateDataKey*",
        "kms:Describe*"
      ],
      "Resource": "*"
    }
  ]
}
POLICY
}

resource "aws_kms_alias" "cloudtrail_key" {
  name          = "alias/cloudtrail_key"
  target_key_id = "${aws_kms_key.cloudtrail_key.id}"
}

# -----------------------------------------------------------
# set up logging bucket
# -----------------------------------------------------------

resource "aws_s3_bucket" "log_bucket" {
  bucket_prefix = "${var.bucket_prefix}"
  acl           = "private"
  region        = "${var.aws_region}"

  versioning {
    enabled = true
  }

  lifecycle {
    prevent_destroy = true
  }

  lifecycle_rule {
    enabled = true
    prefix  = "${var.trail_name}/"

    expiration {
      days = 365
    }

    noncurrent_version_expiration {
      days = 365
    }
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        kms_master_key_id = "${aws_kms_key.log_key.arn}"
        sse_algorithm     = "aws:kms"
      }
    }
  }

  tags = "${merge(map("Name","Log Bucket"), var.tags)}"
}

resource "aws_s3_bucket_policy" "log_bucket_policy" {
  bucket = "${aws_s3_bucket.log_bucket.id}"

  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AWSCloudTrailAclCheck",
      "Effect": "Allow",
      "Principal": {"Service": "cloudtrail.amazonaws.com"},
      "Action": "s3:GetBucketAcl",
      "Resource": "${aws_s3_bucket.log_bucket.arn}"
    },
    {
      "Sid": "AWSCloudTrailWrite",
      "Effect": "Allow",
      "Principal": {"Service": "cloudtrail.amazonaws.com"},
      "Action": "s3:PutObject",
      "Resource": "${aws_s3_bucket.log_bucket.arn}/*",
      "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}}
    },
    {
      "Sid": "AWSCloudWatchAclCheck",
      "Effect": "Allow",
      "Principal": {"Service": "logs.${var.aws_region}.amazonaws.com"},
      "Action": "s3:GetBucketAcl",
      "Resource": "${aws_s3_bucket.log_bucket.arn}"
    },
    {
      "Sid": "AWSCloudWatchWrite",
      "Effect": "Allow",
      "Principal": {"Service": "logs.${var.aws_region}.amazonaws.com"},
      "Action": "s3:PutObject",
      "Resource": "${aws_s3_bucket.log_bucket.arn}/*",
      "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}}
    }
  ]
}
POLICY
}

# -----------------------------------------------------------
# set up log group
# -----------------------------------------------------------
resource "aws_cloudwatch_log_group" "example" {
  name = "example"

  kms_key_id        = "${aws_kms_key.cloudtrail_key.arn}"
  retention_in_days = 90
  tags              = "${merge(map("Name","Example"), var.tags)}"
}

# -----------------------------------------------------------
# set up cloud trail
# -----------------------------------------------------------
resource "aws_cloudtrail" "example" {
  name                          = "${var.trail_name}"
  s3_bucket_name                = "${aws_s3_bucket.log_bucket.id}"
  s3_key_prefix                 = "${var.trail_name}"
  include_global_service_events = true
  enable_logging                = true
  is_multi_region_trail         = false
  enable_log_file_validation    = true
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.example.arn}"

  kms_key_id = "${aws_kms_key.cloudtrail_key.arn}"

  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }

  tags = "${merge(map("Name","Example account audit"), var.tags)}"
}

# -----------------------------------------------------------
# set up flow log
# -----------------------------------------------------------
resource "aws_flow_log" "example" {
  log_group_name = "${aws_cloudwatch_log_group.example.name}"
  iam_role_arn   = "${aws_iam_role.flow_example.arn}"
  vpc_id         = "${aws_vpc.example.id}"
  traffic_type   = "ALL"
}

resource "aws_iam_role" "flow_example" {
  name = "flow-example"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "vpc-flow-logs.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "flow_example" {
  name = "flow-example"
  role = "${aws_iam_role.flow_example.id}"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF
}
