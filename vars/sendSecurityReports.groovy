#!/usr/bin/env groovy

/**
 * vars/sendSecurityReports.groovy
 * Consolidates and emails generated security reports.
 * Dynamically detects which reports were generated (Snyk, Titus, Nuclei)
 * and attaches only existing reports.
 *
 * Usage:
 *   sendSecurityReports(
 *       reportDir: SecurityReportDir,
 *       recipient: 'infra@sgebiz.com',
 *       credentialsId: 'gmail-smtp',
 *       appName: 'Ezyprocure Development',
 *       sonarDashboardUrl: 'https://sonarqube.ezyprocure.com/dashboard?id=Ezyprocure-Development'
 *   )
 */
def call(Map config = [:]) {
    String reportDir         = config.reportDir ?: "/opt/security-reports/${env.JOB_NAME}/${env.BUILD_NUMBER}"
    String recipient         = config.recipient ?: 'infra@sgebiz.com'
    String credentialsId     = config.credentialsId ?: 'gmail-smtp'
    String appName           = config.appName ?: env.JOB_NAME
    String sonarDashboardUrl = config.sonarDashboardUrl ?: ''
    String buildStatus       = currentBuild.currentResult ?: 'SUCCESS'

    echo "============================================================"
    echo "  [DevSecOps] Consolidating and Sending Security Reports"
    echo "  Recipient: ${recipient}"
    echo "  Report Directory: ${reportDir}"
    echo "============================================================"

    withCredentials([
        usernamePassword(
            credentialsId: credentialsId,
            usernameVariable: 'SMTP_USER',
            passwordVariable: 'SMTP_PASS'
        )
    ]) {
        sh """
        set +x
        BOUNDARY="SecurityScanBoundary_\$(date +%s)"
        EMAIL_FILE="security-email.eml"

        # Sanitize Job Name for filenames (remove slashes, spaces)
        SAFE_JOB_NAME="\$(echo "${env.JOB_NAME}" | tr '/' '_' | tr ' ' '_')"
        PREFIX="\${SAFE_JOB_NAME}_build${env.BUILD_NUMBER}"

        # Detect generated report files and prepare custom named attachments
        ATTACHMENTS=""
        HTML_ATTACHMENTS_LIST=""

        if [ -f "${reportDir}/snyk-sca-report.txt" ]; then
            SNYK_ATTACH="\${PREFIX}_snyk-sca-report.txt"
            cp "${reportDir}/snyk-sca-report.txt" "/tmp/\${SNYK_ATTACH}"
            ATTACHMENTS="\${ATTACHMENTS} /tmp/\${SNYK_ATTACH}"
            HTML_ATTACHMENTS_LIST="\${HTML_ATTACHMENTS_LIST}<li><b>Snyk SCA Report:</b> Attached (\${SNYK_ATTACH})</li>"
        fi

        if [ -f "${reportDir}/titus-report.txt" ]; then
            TITUS_ATTACH="\${PREFIX}_titus-report.txt"
            cp "${reportDir}/titus-report.txt" "/tmp/\${TITUS_ATTACH}"
            ATTACHMENTS="\${ATTACHMENTS} /tmp/\${TITUS_ATTACH}"
            HTML_ATTACHMENTS_LIST="\${HTML_ATTACHMENTS_LIST}<li><b>Titus Secret Scan:</b> Attached (\${TITUS_ATTACH})</li>"
        fi

        if [ -f "${reportDir}/nuclei-report.md" ]; then
            NUCLEI_ATTACH="\${PREFIX}_nuclei-report.md"
            cp "${reportDir}/nuclei-report.md" "/tmp/\${NUCLEI_ATTACH}"
            ATTACHMENTS="\${ATTACHMENTS} /tmp/\${NUCLEI_ATTACH}"
            HTML_ATTACHMENTS_LIST="\${HTML_ATTACHMENTS_LIST}<li><b>Nuclei DAST Report:</b> Attached (\${NUCLEI_ATTACH})</li>"
        elif [ -f "${reportDir}/nuclei-report.txt" ]; then
            NUCLEI_ATTACH="\${PREFIX}_nuclei-report.txt"
            cp "${reportDir}/nuclei-report.txt" "/tmp/\${NUCLEI_ATTACH}"
            ATTACHMENTS="\${ATTACHMENTS} /tmp/\${NUCLEI_ATTACH}"
            HTML_ATTACHMENTS_LIST="\${HTML_ATTACHMENTS_LIST}<li><b>Nuclei DAST Report:</b> Attached (\${NUCLEI_ATTACH})</li>"
        fi

        if [ -z "\${HTML_ATTACHMENTS_LIST}" ]; then
            HTML_ATTACHMENTS_LIST="<li>No security reports were generated in this build.</li>"
        fi

        {
            echo "From: \${SMTP_USER}"
            echo "To: ${recipient}"
            echo "Subject: [${env.JOB_NAME} #${env.BUILD_NUMBER}] Security Scan Reports - ${appName}"
            echo "MIME-Version: 1.0"
            echo "Content-Type: multipart/mixed; boundary=\\"\${BOUNDARY}\\""
            echo ""
            echo "--\${BOUNDARY}"
            echo "Content-Type: text/html; charset=UTF-8"
            echo ""
            echo "<html><body>"
            echo "<h2>DevSecOps Security Scan Report</h2>"
            echo "<p><b>Job Name:</b> ${env.JOB_NAME}</p>"
            echo "<p><b>Build Number:</b> #${env.BUILD_NUMBER} (${buildStatus})</p>"
            echo "<p><b>Application:</b> ${appName}</p>"
            echo "<p><b>Attached Reports:</b></p>"
            echo "<ul>"
            echo "\${HTML_ATTACHMENTS_LIST}"
            echo "</ul>"
            echo "<p><a href=\\"${env.BUILD_URL}\\">View Jenkins Build Details</a></p>"
            if [ -n "${sonarDashboardUrl}" ]; then
                echo "<p><a href=\\"${sonarDashboardUrl}\\">View SonarQube Quality Gate</a></p>"
            fi
            echo "<br><p>Regards,<br><b>DevSecOps / Infrastructure Team</b></p>"
            echo "</body></html>"
            echo ""

            # Loop through any discovered attachments
            for file in \${ATTACHMENTS}; do
                if [ -f "\$file" ]; then
                    filename=\$(basename "\$file")
                    echo "--\${BOUNDARY}"
                    echo "Content-Type: application/octet-stream; name=\\"\${filename}\\""
                    echo "Content-Disposition: attachment; filename=\\"\${filename}\\""
                    echo "Content-Transfer-Encoding: base64"
                    echo ""
                    base64 "\$file"
                    echo ""
                fi
            done
            echo "--\${BOUNDARY}--"
        } > "\${EMAIL_FILE}"

        # Clean up temporary attachment files
        for file in \${ATTACHMENTS}; do
            rm -f "\$file"
        done

        # Dispatch email via curl
        curl --url "smtp://smtp.gmail.com:587" --ssl-reqd \
            --mail-from "\${SMTP_USER}" \
            --mail-rcpt "${recipient}" \
            --user "\${SMTP_USER}:\${SMTP_PASS}" \
            --upload-file "\${EMAIL_FILE}" --silent --show-error

        rm -f "\${EMAIL_FILE}"
        echo "Security report email sent successfully to ${recipient}"
        """
    }
}
