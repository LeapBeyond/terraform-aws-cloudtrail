# -----------------------------------------------------------
# set up a VPC, subnet and EC2 instance so we have something to log
# -----------------------------------------------------------

resource "aws_vpc" "example" {
  cidr_block           = "${var.example_vpc_cidr}"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = "${merge(map("Name","log-example"), var.tags)}"
}

resource "aws_internet_gateway" "example" {
  vpc_id = "${aws_vpc.example.id}"
  tags   = "${merge(map("Name","log-example"), var.tags)}"
}

resource "aws_route_table" "example" {
  vpc_id = "${aws_vpc.example.id}"

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = "${aws_internet_gateway.example.id}"
  }

  tags = "${merge(map("Name","log-example"), var.tags)}"
}

resource "aws_route_table_association" "example" {
  subnet_id      = "${aws_subnet.example.id}"
  route_table_id = "${aws_route_table.example.id}"
}

resource "aws_subnet" "example" {
  vpc_id                  = "${aws_vpc.example.id}"
  cidr_block              = "${var.example_subnet_cidr}"
  map_public_ip_on_launch = true

  tags = "${merge(map("Name","log-example"), var.tags)}"
}

# -----------------------------------------------------------
# lock off default NACL, then add a new set
# -----------------------------------------------------------

resource "aws_default_network_acl" "example_default" {
  default_network_acl_id = "${aws_vpc.example.default_network_acl_id}"
  tags                   = "${merge(map("Name","log-example"), var.tags)}"
}

resource "aws_network_acl" "example" {
  vpc_id     = "${aws_vpc.example.id}"
  subnet_ids = ["${aws_subnet.example.id}"]
  tags       = "${merge(map("Name","log-example"), var.tags)}"
}

resource "aws_network_acl_rule" "example_ssh_in" {
  count          = "${length(var.ssh_inbound)}"
  network_acl_id = "${aws_network_acl.example.id}"
  rule_number    = "${100 + count.index}"
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "${var.ssh_inbound[count.index]}"
  from_port      = 22
  to_port        = 22
}

resource "aws_network_acl_rule" "example_ephemeral_in" {
  network_acl_id = "${aws_network_acl.example.id}"
  rule_number    = 200
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 1024
  to_port        = 65535
}

resource "aws_network_acl_rule" "example_ephemeral_out" {
  count          = "${length(var.ssh_inbound)}"
  network_acl_id = "${aws_network_acl.example.id}"
  rule_number    = "${100 + count.index}"
  egress         = true
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "${var.ssh_inbound[count.index]}"
  from_port      = 1024
  to_port        = 65535
}

resource "aws_network_acl_rule" "example_http_out" {
  network_acl_id = "${aws_network_acl.example.id}"
  rule_number    = 200
  egress         = true
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 80
  to_port        = 80
}

# -----------------------------------------------------------
# lock off default Security Group, then add a new set
# -----------------------------------------------------------

resource "aws_default_security_group" "example_default" {
  vpc_id = "${aws_vpc.example.id}"
  tags   = "${merge(map("Name","log-example"), var.tags)}"
}

resource "aws_security_group" "example_ssh_access" {
  name        = "example-ssh"
  description = "allows ssh access to the example host"
  vpc_id      = "${aws_vpc.example.id}"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["${var.ssh_inbound}"]
  }

  egress {
    from_port   = 1024
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["${var.ssh_inbound}"]
  }
}

resource "aws_security_group" "http_out_access" {
  name        = "example-http-out"
  description = "allows instance to reach out on port 80"
  vpc_id      = "${aws_vpc.example.id}"

  ingress {
    from_port   = 1024
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# -----------------------------------------------------------
# finally, create an EC2 instance
# -----------------------------------------------------------

data "aws_ami" "target_ami" {
  most_recent = true

  filter {
    name   = "owner-alias"
    values = ["amazon"]
  }

  filter {
    name   = "name"
    values = ["${var.ami_name}"]
  }
}

resource "aws_instance" "example" {
  ami           = "${data.aws_ami.target_ami.id}"
  instance_type = "${var.instance_type}"
  key_name      = "${var.example_key}"
  subnet_id     = "${aws_subnet.example.id}"

  vpc_security_group_ids = [
    "${aws_security_group.example_ssh_access.id}",
    "${aws_security_group.http_out_access.id}",
  ]

  root_block_device = {
    volume_type = "gp2"
    volume_size = "${var.root_vol_size}"
  }

  tags        = "${merge(map("Name","log-example"), var.tags)}"
  volume_tags = "${var.tags}"

  user_data = <<EOF
#!/bin/bash
yum update -y -q
yum erase -y -q ntp*
yum -y -q install chrony git
service chronyd start
EOF
}
