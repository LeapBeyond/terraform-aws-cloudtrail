variable "tags" {
  default = {
    "owner"   = "rahook"
    "project" = "cloudtrail-test"
    "client"  = "Internal"
  }
}

variable "bucket_prefix" {
  default = "example-logs"
}

variable "trail_name" {
  default = "example-trail"
}

variable "example_vpc_cidr" {
  default = "172.24.0.0/16"
}

variable "example_subnet_cidr" {
  default = "172.24.0.0/24"
}

variable "ami_name" {
  default = "amzn2-ami-hvm-2017.12.0.20180115-x86_64-gp2"
}

variable "root_vol_size" {
  default = 8
}

variable "instance_type" {
  default = "t2.micro"
}

variable "example_user" {
  default = "ec2-user"
}

variable "lambda_function_name" {
  default = "flow-export-example"
}

variable "aws_account_id" {}
variable "aws_profile" {}
variable "aws_region" {}

variable "ssh_inbound" {
  type = "list"
}

variable "example_key" {}
variable "log_reader" {}
