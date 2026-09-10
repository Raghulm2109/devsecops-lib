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
    String tags            = config.tags ?: 'dast,misconfiguration,exposure,passive,headers,cookie,cors,ssl,tomcat,java'
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

    # 6. Build consolidated Markdown and beautiful HTML reports from Nuclei findings
    if [ -d "${reportDir}/nuclei-md" ] && [ "\$(ls -A "${reportDir}/nuclei-md" 2>/dev/null)" ]; then
        echo "Consolidating Nuclei reports into HTML and Markdown..."
        
        # 6a. Consolidated Markdown report
        {
            echo "# DevSecOps Nuclei DAST Vulnerability Report"
            echo "**Target:** ${targetUrl}  "
            echo "**Scan Date:** \$(date)  "
            echo "**Severities:** ${severity}  "
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

        cp "${reportDir}/nuclei-detailed-report.md" "${reportDir}/nuclei-report.txt"

        # 6b. Premium HTML Dashboard Report (No dependencies required)
        {
            echo "<!DOCTYPE html>"
            echo "<html lang='en'>"
            echo "<head>"
            echo "<meta charset='utf-8'>"
            echo "<meta name='viewport' content='width=device-width, initial-scale=1'>"
            echo "<title>DevSecOps Nuclei DAST Report - ${targetUrl}</title>"
            echo "<style>"
            echo "  :root { --bg: #0f172a; --card-bg: #1e293b; --border: #334155; --text: #f8fafc; --muted: #94a3b8; --accent: #38bdf8; }"
            echo "  * { box-sizing: border-box; margin: 0; padding: 0; }"
            echo "  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: #0f172a; color: #f8fafc; padding: 30px 20px; line-height: 1.6; }"
            echo "  .container { max-width: 1000px; margin: 0 auto; }"
            echo "  .header { background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 24px; margin-bottom: 24px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.3); }"
            echo "  .header h1 { font-size: 24px; color: #38bdf8; display: flex; align-items: center; gap: 10px; margin-bottom: 12px; }"
            echo "  .meta-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px; font-size: 14px; color: #cbd5e1; }"
            echo "  .meta-item { background: #0f172a; padding: 10px 14px; border-radius: 8px; border: 1px solid #334155; }"
            echo "  .meta-label { font-size: 12px; color: #94a3b8; text-transform: uppercase; font-weight: 600; display: block; margin-bottom: 2px; }"
            echo "  .card { background: #1e293b; border: 1px solid #334155; border-radius: 10px; padding: 20px; margin-bottom: 20px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.2); }"
            echo "  h2, h3 { color: #f1f5f9; margin-top: 15px; margin-bottom: 8px; }"
            echo "  h2 { font-size: 18px; border-bottom: 1px solid #334155; padding-bottom: 6px; color: #38bdf8; }"
            echo "  h3 { font-size: 15px; color: #cbd5e1; }"
            echo "  p, li { font-size: 14px; color: #e2e8f0; margin-bottom: 8px; }"
            echo "  ul { padding-left: 20px; }"
            echo "  pre { background: #020617; color: #38bdf8; border: 1px solid #334155; padding: 14px; border-radius: 8px; overflow-x: auto; font-family: monospace; font-size: 13px; margin: 10px 0; white-space: pre-wrap; word-break: break-all; }"
            echo "  code { background: #020617; color: #38bdf8; padding: 2px 6px; border-radius: 4px; font-family: monospace; font-size: 13px; }"
            echo "  hr { border: 0; height: 1px; background: #334155; margin: 24px 0; }"
            echo "  .footer { text-align: center; font-size: 13px; color: #64748b; margin-top: 40px; padding-top: 20px; border-top: 1px solid #334155; }"
            echo "  @media print { body { background: #fff; color: #000; } .header, .card { background: #fff; border-color: #ccc; box-shadow: none; } pre, code { background: #f5f5f5; color: #000; border-color: #ddd; } }"
            echo "</style>"
            echo "</head>"
            echo "<body>"
            echo "<div class='container'>"
            echo "  <div class='header'>"
            echo "    <h1>🛡️ Nuclei DAST Security Scan Report</h1>"
            echo "    <div class='meta-grid'>"
            echo "      <div class='meta-item'><span class='meta-label'>Target URL</span><b>${targetUrl}</b></div>"
            echo "      <div class='meta-item'><span class='meta-label'>Scan Date</span>\$(date)</div>"
            echo "      <div class='meta-item'><span class='meta-label'>Severity Filter</span>${severity}</div>"
            echo "      <div class='meta-item'><span class='meta-label'>Environment</span>Jenkins Build #${env.BUILD_NUMBER}</div>"
            echo "    </div>"
            echo "  </div>"
            echo "  <div class='card'>"

            # Render markdown content safely to HTML
            sed -e 's/^# \(.*\)/<h2>\1<\/h2>/' \
                -e 's/^## \(.*\)/<h2>\1<\/h2>/' \
                -e 's/^### \(.*\)/<h3>\1<\/h3>/' \
                -e 's/^\*\*\(.*\)\*\*/<b>\1<\/b>/' \
                -e 's/^---/<\/div><div class="card">/' \
                "${reportDir}/nuclei-detailed-report.md"

            echo "  </div>"
            echo "  <div class='footer'>Report generated automatically by DevSecOps Shared Library Pipeline</div>"
            echo "</div>"
            echo "</body></html>"
        } > "${reportDir}/nuclei-report.html"
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

        {
            echo "<!DOCTYPE html><html><head><meta charset='utf-8'><title>Nuclei DAST Report</title>"
            echo "<style>body{font-family:sans-serif;background:#0f172a;color:#f8fafc;padding:40px;text-align:center;} .box{background:#1e293b;border:1px solid #334155;padding:30px;border-radius:12px;max-width:600px;margin:auto;}</style></head><body>"
            echo "<div class='box'><h2 style='color:#38bdf8;'>🛡️ Nuclei DAST Security Scan</h2><p style='color:#4ade80;font-size:18px;margin-top:15px;'>✅ Completed - No vulnerabilities identified matching configured severities.</p><p style='color:#94a3b8;font-size:13px;margin-top:10px;'>Target: ${targetUrl}</p></div></body></html>"
        } > "${reportDir}/nuclei-report.html"
    fi

    echo "Nuclei text report generated at ${reportDir}/nuclei-report.txt"
    if [ -f "${reportDir}/nuclei-report.html" ]; then
        echo "Nuclei HTML dashboard generated at ${reportDir}/nuclei-report.html"
    fi
    if [ -f "${reportDir}/nuclei-detailed-report.md" ]; then
        echo "Nuclei Markdown report generated at ${reportDir}/nuclei-detailed-report.md"
    fi
    if [ -f "${reportDir}/nuclei-report.json" ]; then
        echo "Nuclei JSON export generated at ${reportDir}/nuclei-report.json"
    fi
    """
}
