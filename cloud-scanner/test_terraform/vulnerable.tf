# Intentionally vulnerable Terraform file for scanner validation.
# Do not deploy this configuration.

resource "aws_s3_bucket" "public_data" {
  bucket = "company-public-data"
  acl    = "public-read"
}

resource "aws_security_group" "web" {
  name = "web-sg"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "prod" {
  identifier = "prod-db"
  engine     = "mysql"
}

resource "aws_instance" "web" {
  ami                         = "ami-0c55b159cbfafe1f0"
  instance_type               = "t3.micro"
  associate_public_ip_address = true
}

resource "azurerm_storage_account" "public_storage" {
  name                     = "publicstorageacct"
  resource_group_name      = "demo"
  location                 = "westeurope"
  account_tier             = "Standard"
  account_replication_type = "LRS"
  allow_blob_public_access = true
  min_tls_version          = "TLS1_0"
}

resource "google_storage_bucket_iam_member" "public" {
  bucket = "company-data-lake"
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}
