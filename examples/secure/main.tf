resource "aws_s3_bucket" "private_assets" {
  bucket = "demo-private-assets-example"
}

resource "aws_s3_bucket_public_access_block" "private_assets" {
  bucket                  = aws_s3_bucket.private_assets.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_security_group" "web" {
  name = "demo-web"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_ebs_volume" "data" {
  availability_zone = "eu-west-2a"
  size              = 40
  encrypted         = true
}

