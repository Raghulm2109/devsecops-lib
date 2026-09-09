#!/usr/bin/env groovy

/**
 * vars/runSonarScan.groovy
 * Executes SonarQube Scanner CLI Analysis
 *
 * Usage:
 *   runSonarScan(
 *       projectKey: 'Ezyprocure-Development',
 *       projectName: 'Ezyprocure-Development',
 *       credentialsId: 'sonar-token',
 *       sonarHostUrl: 'http://10.9.3.15:9000'
 *   )
 */
def call(Map config = [:]) {
    String projectKey    = config.projectKey ?: 'Ezyprocure-Development'
    String projectName   = config.projectName ?: projectKey
    String credentialsId = config.credentialsId ?: 'sonar-token'
    String sonarHostUrl  = config.sonarHostUrl ?: 'http://10.9.3.15:9000'
    String settingsFile  = config.settingsFile ?: '/home/devjenkins/sonar-project.properties'
    String scannerJar    = config.scannerJar ?: '/home/devjenkins/sonar-scanner-4.6.2.2472-linux/lib/sonar-scanner-cli-4.6.2.2472.jar'
    String javaBin       = config.javaBin ?: '/usr/lib/jvm/java-17-openjdk-amd64/bin/java'

    echo "============================================================"
    echo "  [DevSecOps] Executing SonarQube Scanner"
    echo "  Project: ${projectKey}"
    echo "  Sonar Server: ${sonarHostUrl}"
    echo "============================================================"

    withCredentials([string(credentialsId: credentialsId, variable: 'SONAR_TOKEN')]) {
        sh """
        ${javaBin} -jar ${scannerJar} \
            -Dproject.settings=${settingsFile} \
            -Dsonar.working.directory=/tmp/.scannerwork \
            -Dsonar.host.url=${sonarHostUrl} \
            -Dsonar.login="\$SONAR_TOKEN" \
            -Dsonar.projectName="${projectName}" \
            -Dsonar.projectKey="${projectKey}" || true

        rm -rf /tmp/.scannerwork
        """
    }
}
