// NAS Financial — Terraform CI/CD (Declarative Pipeline)
//
// --- Source from GitHub ---
// 1. Push this repo (including Jenkinsfile) to GitHub.
// 2. In Jenkins: New Item → "Multibranch Pipeline" (recommended) OR "Pipeline" with "Pipeline script from SCM".
// 3. SCM: Git → Repository URL: https://github.com/<YOUR_USER>/<YOUR_REPO>.git
//    Credentials: add a Jenkins credential (Username + Password) using your GitHub username and a
//    Personal Access Token (classic) with repo scope — not your GitHub password.
// 4. Branch: Multibranch discovers branches; for a single Pipeline job, set Branch Specifier to */main.
// 5. Script Path: Jenkinsfile (default — file must live at repo root of what you clone).
// 6. Optional: GitHub → Settings → Webhooks → point to Jenkins so pushes trigger builds (or use SCM polling).
//
// The `checkout scm` step below checks out whatever GitHub repo/branch the job is bound to.
//
// --- If your Terraform lives in a subfolder of a monorepo ---
// Wrap each `sh` in: dir('NAS-Financial-aws-terraform') { ... }
//
// --- Other Jenkins setup ---
//   - Terraform on the agent (Linux recommended)
//   - Secret file credential ID: nas-financial-tfvars → terraform.tfvars (secrets stay out of GitHub)
//   - AWS: agent IAM role or Jenkins AWS credentials for S3 state + deploy (see providers.tf)

pipeline {
  agent any

  parameters {
    booleanParam(name: 'APPLY', defaultValue: false, description: 'If checked (and branch is main), prompt to terraform apply after plan')
  }

  options {
    timestamps()
    timeout(time: 45, unit: 'MINUTES')
    disableConcurrentBuilds()
  }

  environment {
    TF_IN_AUTOMATION = 'true'
  }

  stages {
    stage('Checkout') {
      steps {
        checkout scm
      }
    }

    stage('Terraform format (check)') {
      steps {
        sh 'terraform fmt -check -recursive || (echo "Run locally: terraform fmt -recursive" && exit 1)'
      }
    }

    stage('Terraform init') {
      steps {
        sh 'terraform init -input=false'
      }
    }

    stage('Terraform validate') {
      steps {
        sh 'terraform validate'
      }
    }

    stage('Terraform plan') {
      steps {
        withCredentials([file(credentialsId: 'nas-financial-tfvars', variable: 'TFVARS')]) {
          sh 'terraform plan -input=false -var-file="$TFVARS" -out=tfplan'
        }
      }
    }

    stage('Archive plan') {
      steps {
        archiveArtifacts artifacts: 'tfplan', fingerprint: true, allowEmptyArchive: false
      }
    }

    stage('Terraform apply') {
      when {
        allOf {
          branch 'main'
          expression { return params.APPLY == true }
        }
      }
      steps {
        input message: 'Apply Terraform to AWS (NAS Financial)?', ok: 'Apply'
        withCredentials([file(credentialsId: 'nas-financial-tfvars', variable: 'TFVARS')]) {
          sh 'terraform apply -input=false tfplan'
        }
      }
    }
  }

  post {
    always {
      sh 'rm -f tfplan || true'
    }
    success { echo 'NAS Financial Terraform pipeline finished successfully.' }
    failure { echo 'Pipeline failed — check init / validate / plan logs.' }
  }
}
