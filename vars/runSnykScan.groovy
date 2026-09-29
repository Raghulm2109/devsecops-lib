#!/usr/bin/env groovy

/**
 * vars/runSnykScan.groovy
 * Executes Snyk SCA / Open Source Dependency Vulnerability Scan
 *
 * Usage:
 *   runSnykScan(
 *       orgId: '86ab3384-bcaa-49c8-8311-3f18b98f7321',
 *       reportDir: SecurityReportDir,
 *       credentialsId: 'snyk-token'
 *   )
 */
def call(Map config = [:]) {
    String reportDir     = config.reportDir ?: "/opt/security-reports/${env.JOB_NAME}/${env.BUILD_NUMBER}"
    String orgId         = config.orgId ?: '86ab3384-bcaa-49c8-8311-3f18b98f7321'
    String credentialsId = config.credentialsId ?: 'snyk-token'
    boolean failOnError  = config.failOnError ?: false

    echo "============================================================"
    echo "  [DevSecOps] Executing Snyk SCA Scan"
    echo "  Org ID: ${orgId}"
    echo "  Report Dir: ${reportDir}"
    echo "============================================================"

    withCredentials([string(credentialsId: credentialsId, variable: 'SNYK_TOKEN')]) {
        sh """
        mkdir -p "${reportDir}"
        snyk --version || true

        # Run Snyk SCA Scan:
        # 1. Output machine-readable JSON to snyk-sca-report.json
        # 2. Capture human-readable CLI report directly to snyk-sca-report.txt (stripping ANSI color codes)
        # 3. Mirror output to console via tee
        NO_COLOR=1 TERM=dumb snyk test --org=${orgId} \
            --json-file-output="${reportDir}/snyk-sca-report.json" 2>&1 \
            | sed -E 's/(\\x1b)?\\[[0-9;]*[a-zA-Z]//g; s/\\b[0-9]+;[0-9]+m//g' \
            | tee "${reportDir}/snyk-sca-report.txt" || true

        # Ensure the text report is never empty
        if [ ! -s "${reportDir}/snyk-sca-report.txt" ]; then
            if [ -s "${reportDir}/snyk-sca-report.json" ]; then
                echo "Snyk scan completed. Raw output below:" > "${reportDir}/snyk-sca-report.txt"
                cat "${reportDir}/snyk-sca-report.json" >> "${reportDir}/snyk-sca-report.txt"
            else
                echo "Snyk scan completed with no report output." > "${reportDir}/snyk-sca-report.txt"
            fi
        fi

        echo "Snyk report generated at ${reportDir}/snyk-sca-report.txt (\$(wc -c < "${reportDir}/snyk-sca-report.txt" 2>/dev/null || echo 0) bytes)"
        """
    }
}
