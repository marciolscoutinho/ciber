# Example Terraform file with safer defaults.

resource "aws_s3_bucket" "private_data" {
  bucket = "company-private-data"
}

resource "aws_s3_bucket_public_access_block" "private_data" {
  bucket                  = aws_s3_bucket.private_data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_security_group" "admin" {
  name = "admin-sg"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["203.0.113.10/32"]
  }
}

resource "aws_db_instance" "prod" {
  identifier        = "prod-db"
  engine            = "mysql"
  storage_encrypted = true
}
