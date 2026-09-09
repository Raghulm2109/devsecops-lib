#!/usr/bin/env groovy

/**
 * vars/runZapScan.groovy
 * Executes OWASP ZAP DAST Vulnerability Scan
 *
 * Usage:
 *   runZapScan(
 *       targetUrl: 'https://dev.ezyprocure.com',
 *       reportDir: SecurityReportDir,
 *       maxWaitAttempts: 45
 *   )
 */
def call(Map config = [:]) {
    String targetUrl       = config.targetUrl ?: 'https://dev.ezyprocure.com'
    String reportDir       = config.reportDir ?: "/opt/security-reports/${env.JOB_NAME}/${env.BUILD_NUMBER}"
    int maxWaitAttempts    = config.maxWaitAttempts ?: 45
    String zapBin          = config.zapBin ?: '/usr/local/bin/zap'
    String javaHome        = config.javaHome ?: '/usr/lib/jvm/java-17-openjdk-amd64'

    echo "============================================================"
    echo "  [DevSecOps] Executing OWASP ZAP DAST Scan"
    echo "  Target: ${targetUrl}"
    echo "  Report Dir: ${reportDir}"
    echo "============================================================"

    sh """
    echo "Checking application health at ${targetUrl}..."
    count=1
    while [ \$count -le ${maxWaitAttempts} ]; do
        if curl -k -s -f -o /dev/null "${targetUrl}"; then
            echo "Application is online and responding."
            break
        fi
        echo "Waiting for application startup (\$count/${maxWaitAttempts})..."
        sleep 10
        count=\$((count + 1))
    done

    mkdir -p "${reportDir}"
    JAVA_HOME=${javaHome} \
        ${zapBin} \
        -cmd \
        -port 8090 \
        -quickurl "${targetUrl}" \
        -quickout "${reportDir}/zap-report.html" \
        -quickprogress \
        -config spider.maxDuration=2 \
        -config spider.maxDepth=3 \
        -config scanner.maxScanDurationInMins=3 \
        -config scanner.threadPerHost=10 \
        -config connection.timeoutInSecs=15 \
        || true

    echo "ZAP report generated at ${reportDir}/zap-report.html"
    """
}
