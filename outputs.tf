output "encryption_key_arn" {
  value = "${aws_kms_key.log_key.arn}"
}

output "log_bucket_arn" {
  value = "${aws_s3_bucket.log_bucket.arn}"
}

output "trail_arn" {
  value = "${aws_cloudtrail.example.arn}"
}

output "public_dns" {
  value = "${aws_instance.example.public_dns}"
}

output "private_dns" {
  value = "${aws_instance.example.private_dns}"
}

output "connect_string" {
  value = "ssh -i ${var.example_key}.pem ${var.example_user}@${aws_instance.example.public_dns}"
}
