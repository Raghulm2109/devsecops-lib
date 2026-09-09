#!/usr/bin/env groovy

/**
 * vars/runTitusScan.groovy
 * Executes Titus Secret Scanner (Praetorian)
 *
 * Usage:
 *   runTitusScan(
 *       reportDir: SecurityReportDir
 *   )
 */
def call(Map config = [:]) {
    String reportDir = config.reportDir ?: "/opt/security-reports/${env.JOB_NAME}/${env.BUILD_NUMBER}"

    echo "============================================================"
    echo "  [DevSecOps] Executing Titus Secret Scan"
    echo "  Report Dir: ${reportDir}"
    echo "============================================================"

    sh """
    mkdir -p "${reportDir}"
    rm -rf /tmp/titus.ds

    # 1. Scan directory with Titus
    /usr/local/bin/titus scan . --output /tmp/titus.ds || true

    # 2. Generate human-readable report without ANSI escape codes
    NO_COLOR=1 TERM=dumb /usr/local/bin/titus report --datastore /tmp/titus.ds \
        | sed -E 's/(\\x1b)?\\[[0-9;]*[a-zA-Z]//g; s/\\b[0-9]+;[0-9]+m//g' \
        > "${reportDir}/titus-report.txt" || true

    # 3. Generate JSON report
    /usr/local/bin/titus report --datastore /tmp/titus.ds --format json \
        > "${reportDir}/titus-report.json" 2>/dev/null || true

    rm -rf /tmp/titus.ds
    echo "Titus reports generated at ${reportDir}"
    """
}
