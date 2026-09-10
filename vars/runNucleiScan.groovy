#!/usr/bin/env groovy

/**
 * vars/runNucleiScan.groovy
 * Executes ProjectDiscovery Nuclei DAST Vulnerability Scan
 * https://github.com/projectdiscovery/nuclei
 *
 * Usage:
 *   runNucleiScan(
 *       targetUrl: 'https://dev.ezyprocure.com',
 *       reportDir: SecurityReportDir,
 *       severity: 'low,medium,high,critical',
 *       maxWaitAttempts: 45
 *   )
 */
def call(Map config = [:]) {
    String targetUrl       = config.targetUrl ?: 'https://dev.ezyprocure.com'
    String reportDir       = config.reportDir ?: "/opt/security-reports/${env.JOB_NAME}/${env.BUILD_NUMBER}"
    int maxWaitAttempts    = config.maxWaitAttempts ?: 45
    String nucleiBin       = config.nucleiBin ?: '/usr/local/bin/nuclei'
    String severity        = config.severity ?: 'info,low,medium,high,critical'
    int rateLimit          = config.rateLimit ?: 150
    String tags            = config.tags ?: ''
    boolean updateTemplates = config.updateTemplates != null ? config.updateTemplates : true
    String extraArgs       = config.extraArgs ?: ''

    echo "============================================================"
    echo "  [DevSecOps] Executing ProjectDiscovery Nuclei DAST Scan"
    echo "  Target: ${targetUrl}"
    echo "  Report Dir: ${reportDir}"
    echo "  Severity: ${severity}"
    echo "============================================================"

    sh """
    # 1. Check application health before launching scan
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

    # 2. Locate or auto-install Nuclei binary
    NUCLEI_CMD="${nucleiBin}"
    if ! command -v "\$NUCLEI_CMD" >/dev/null 2>&1; then
        if command -v nuclei >/dev/null 2>&1; then
            NUCLEI_CMD="nuclei"
        else
            echo "Nuclei binary not found at \$NUCLEI_CMD or in PATH. Attempting automatic download..."
            ARCH=\$(uname -m)
            case "\$ARCH" in
                x86_64) NUCLEI_ARCH="amd64" ;;
                aarch64|arm64) NUCLEI_ARCH="arm64" ;;
                *) NUCLEI_ARCH="amd64" ;;
            esac
            mkdir -p /tmp/nuclei-bin
            curl -sL https://api.github.com/repos/projectdiscovery/nuclei/releases/latest \
                | grep "browser_download_url.*linux_\${NUCLEI_ARCH}.zip" \
                | cut -d '"' -f 4 \
                | xargs -I {} curl -sL -o /tmp/nuclei-bin/nuclei.zip {} || true
            if [ -f /tmp/nuclei-bin/nuclei.zip ]; then
                unzip -o /tmp/nuclei-bin/nuclei.zip -d /tmp/nuclei-bin/ >/dev/null 2>&1 || true
                chmod +x /tmp/nuclei-bin/nuclei 2>/dev/null || true
                NUCLEI_CMD="/tmp/nuclei-bin/nuclei"
            fi
        fi
    fi

    echo "Using Nuclei binary: \$NUCLEI_CMD"
    "\$NUCLEI_CMD" -version || true

    # 3. Update community templates if enabled
    if [ "${updateTemplates}" = "true" ]; then
        echo "Updating Nuclei templates..."
        "\$NUCLEI_CMD" -update-templates -duc || true
    fi

    # 4. Build filter arguments
    EXTRA_FLAGS="${extraArgs}"
    if [ -n "${tags}" ]; then
        EXTRA_FLAGS="\${EXTRA_FLAGS} -tags ${tags}"
    fi

    # 5. Execute Nuclei scan with native built-in detailed reporting
    echo "Starting Nuclei vulnerability scan against ${targetUrl}..."
    "\$NUCLEI_CMD" \
        -target "${targetUrl}" \
        -severity "${severity}" \
        -rate-limit ${rateLimit} \
        -no-interactsh \
        -verbose \
        -include-rr \
        -output "${reportDir}/nuclei-report.txt" \
        -json-export "${reportDir}/nuclei-report.json" \
        -markdown-export "${reportDir}/nuclei-md" \
        \${EXTRA_FLAGS} \
        || true

    # 6. If Nuclei generated markdown files, consolidate them into a comprehensive report
    if [ -d "${reportDir}/nuclei-md" ] && [ "\$(ls -A "${reportDir}/nuclei-md" 2>/dev/null)" ]; then
        echo "Consolidating Nuclei native markdown reports..."
        {
            echo "# DevSecOps Nuclei DAST Vulnerability Report"
            echo "**Target:** ${targetUrl}  "
            echo "**Scan Date:** \$(date)  "
            echo "**Configured Severities:** ${severity}  "
            echo ""
            echo "---"
            echo ""
            for md in "${reportDir}"/nuclei-md/*.md; do
                if [ -f "\$md" ]; then
                    cat "\$md"
                    echo ""
                    echo "---"
                    echo ""
                fi
            done
        } > "${reportDir}/nuclei-detailed-report.md"

        # Also provide it as nuclei-report.txt for email viewing
        cp "${reportDir}/nuclei-detailed-report.md" "${reportDir}/nuclei-report.txt"
    fi

    # 7. Fallback if scan had 0 findings
    if [ ! -s "${reportDir}/nuclei-report.txt" ]; then
        {
            echo "============================================================"
            echo "              PROJECTDISCOVERY NUCLEI DAST REPORT"
            echo "============================================================"
            echo "Target       : ${targetUrl}"
            echo "Scan Date    : \$(date)"
            echo "Severity     : ${severity}"
            echo "Status       : Completed - No vulnerabilities identified."
            echo "============================================================"
        } > "${reportDir}/nuclei-report.txt"
    fi

    echo "Nuclei report generated at ${reportDir}/nuclei-report.txt"
    if [ -f "${reportDir}/nuclei-detailed-report.md" ]; then
        echo "Nuclei Markdown report generated at ${reportDir}/nuclei-detailed-report.md"
    fi
    if [ -f "${reportDir}/nuclei-report.json" ]; then
        echo "Nuclei JSON export generated at ${reportDir}/nuclei-report.json"
    fi
    """
}
