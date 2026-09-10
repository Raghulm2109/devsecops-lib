# DevSecOps Jenkins Shared Library

This repository contains modular, reusable DevSecOps security stages for Jenkins pipelines.

## Directory Layout
```
.
└── vars/
    ├── runSnykScan.groovy         # Snyk SCA / dependency scanner
    ├── runTitusScan.groovy        # Titus secret scanner
    ├── runSonarScan.groovy        # SonarQube CLI scanner
    ├── runNucleiScan.groovy       # ProjectDiscovery Nuclei DAST scanner
    ├── runZapScan.groovy          # OWASP ZAP DAST scanner (legacy)
    └── sendSecurityReports.groovy # Email consolidation & notification
```

## How to Register in Jenkins

1. Go to **Jenkins Dashboard** -> **Manage Jenkins** -> **System** (or **Configure System**).
2. Scroll to **Global Pipeline Libraries**.
3. Click **Add**:
   - **Name:** `devsecops-lib`
   - **Default version:** `main` (or `master`)
   - **Retrieval method:** Modern SCM -> **Git**
   - **Project Repository:** URL to this repository (e.g. `git@bitbucket.org:your-org/jenkins-shared-library.git`)
   - **Credentials:** Your Jenkins Git credential (e.g. `stgjenkins`)
4. Click **Save**.

## How to Use in any Jenkinsfile

```groovy
@Library('devsecops-lib') _

pipeline {
    agent any
    parameters {
        booleanParam(name: 'RUN_SNYK', defaultValue: false, description: 'Run Snyk scan')
    }
    stages {
        stage('Snyk Scan') {
            when { expression { return params.RUN_SNYK == true } }
            steps {
                runSnykScan(
                    orgId: '86ab3384-bcaa-49c8-8311-3f18b98f7321',
                    reportDir: "/opt/security-reports/${env.JOB_NAME}/${env.BUILD_NUMBER}"
                )
            }
        }
    }
}
```
