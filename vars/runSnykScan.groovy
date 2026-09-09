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

        # Run Snyk SCA Scan and export JSON
        snyk test --org=${orgId} \
            --json-file-output="${reportDir}/snyk-sca-report.json" || true

        # Format JSON into human-readable summary if report exists
        if [ -f "${reportDir}/snyk-sca-report.json" ]; then
            jq -r '
                "============================================================",
                "                    SNYK SCA REPORT",
                "============================================================",
                "",
                "Status          : " + (if .ok == true then "PASS" else "FAIL" end),
                "Summary         : " + (.summary // "N/A"),
                "Package Manager : " + (.packageManager // "N/A"),
                "Target          : " + (.displayTargetFile // "N/A"),
                "Dependency Count: " + ((.dependencyCount // 0) | tostring),
                "Vulnerabilities : " + ((.uniqueCount // 0) | tostring),
                "",
                "------------------------------------------------------------",
                "VULNERABILITY DETAILS",
                "------------------------------------------------------------",
                "",
                (if ((.vulnerabilities // []) | length) == 0 then
                    "No known vulnerabilities found."
                else
                    (.vulnerabilities[] |
                     "Package  : " + (.packageName // "N/A") +
                     "\\nSeverity : " + (.severity // "N/A") +
                     "\\nCVSS     : " + ((.cvssScore // "N/A") | tostring) +
                     "\\nIssue    : " + (.title // .id // "N/A") +
                     "\\nCVE      : " + (if ((.identifiers.CVE // []) | length) > 0 then (.identifiers.CVE | join(", ")) else "N/A" end) +
                     "\\nFixed In : " + (if ((.fixedIn // []) | length) > 0 then (.fixedIn | join(", ")) else "Not available" end) + "\\n")
                end),
                "============================================================",
                "                    END OF REPORT",
                "============================================================"
            ' "${reportDir}/snyk-sca-report.json" > "${reportDir}/snyk-sca-report.txt" || true
            echo "Snyk report generated at ${reportDir}/snyk-sca-report.txt"
        else
            echo "Snyk JSON report not found." > "${reportDir}/snyk-sca-report.txt"
        fi
        """
    }
}
