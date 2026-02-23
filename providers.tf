# use the AWS provider to deploy to us-east-1 region
provider "aws" {
  region = "us-east-1"
}

# DR region for cross-region backups (application & database tier)
provider "aws" {
  alias  = "dr"
  region = "us-west-2"
}

terraform {
  backend "s3" {
    bucket         = "terraform-state-fidelis-bucket"
    key            = "nas-folder/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
  }
}