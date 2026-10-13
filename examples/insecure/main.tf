provider "aws" {
  region = "eu-west-2"
}

# Intentionally insecure: public ACL, broad SSH exposure, and unencrypted storage.
resource "aws_s3_bucket" "public_assets" {
  bucket = "demo-public-assets-example"
  acl    = "public-read"
}

resource "aws_security_group" "admin" {
  name = "demo-admin-access"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_ebs_volume" "data" {
  availability_zone = "eu-west-2a"
  size              = 40
}

resource "aws_cloudtrail" "audit" {
  name                          = "demo-audit-trail"
  s3_bucket_name                = "demo-audit-logs"
  enable_log_file_validation    = false
}

