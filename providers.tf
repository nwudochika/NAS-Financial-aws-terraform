# use the AWS provider to deploy to us-east-1 region
provider "aws" {
  region = "us-east-1"
}

# DR region for cross-region backups (application & database tier)
provider "aws" {
  alias  = "dr"
  region = "us-west-2"
}