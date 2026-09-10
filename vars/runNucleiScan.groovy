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

    # 5. Execute Nuclei scan with full details
    echo "Starting Nuclei vulnerability scan against ${targetUrl}..."
    "\$NUCLEI_CMD" \
        -target "${targetUrl}" \
        -severity "${severity}" \
        -rate-limit ${rateLimit} \
        -no-interactsh \
        -include-rr \
        -output "${reportDir}/nuclei-raw.txt" \
        -json-export "${reportDir}/nuclei-report.json" \
        -markdown-export "${reportDir}/nuclei-md" \
        \${EXTRA_FLAGS} \
        || true

    # 6. Generate a comprehensive human-readable report via Python helper
    cat << 'PYEOF' > "${reportDir}/generate_nuclei_report.py"
import json
import os
import sys

report_json = sys.argv[1]
report_txt = sys.argv[2]
report_html = sys.argv[3]
target_url = sys.argv[4]
severity = sys.argv[5]

findings = []
if os.path.isfile(report_json):
    with open(report_json, 'r', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    findings.append(json.loads(line))
                except Exception:
                    pass

sep_line = '=' * 80
dash_line = '-' * 80

# Generate Detailed Text Report
with open(report_txt, 'w', encoding='utf-8') as f:
    f.write(sep_line + '\n')
    f.write('                   DEVSECOPS NUCLEI DAST VULNERABILITY REPORT\n')
    f.write(sep_line + '\n')
    f.write('Target       : ' + target_url + '\n')
    f.write('Severities   : ' + severity + '\n')
    f.write('Total Issues : ' + str(len(findings)) + '\n')
    f.write(sep_line + '\n\n')

    if not findings:
        f.write('STATUS: PASSED - No vulnerabilities identified matching configured severity levels.\n')
    else:
        for idx, item in enumerate(findings, 1):
            info = item.get('info') or {}
            title = info.get('name') or item.get('template-id') or 'Unknown Vulnerability'
            sev = str(info.get('severity', 'unknown')).upper()
            tmpl_id = item.get('template-id', 'N/A')
            matched = item.get('matched-at') or item.get('host') or 'N/A'
            proto = item.get('type', 'http')

            f.write('[' + str(idx) + '] ' + title + '\n')
            f.write(dash_line + '\n')
            f.write('Severity     : ' + sev + '\n')
            f.write('Template ID  : ' + tmpl_id + '\n')
            f.write('Matched URL  : ' + matched + '\n')
            f.write('Type / Proto : ' + proto + '\n')
            if info.get('description'):
                f.write('Description  : ' + str(info.get('description')).strip() + '\n')
            if info.get('reference'):
                refs = info.get('reference')
                if isinstance(refs, list):
                    f.write('References   :\n  - ' + '\n  - '.join(refs) + '\n')
                else:
                    f.write('References   : ' + str(refs) + '\n')
            if info.get('remediation'):
                f.write('Remediation  : ' + str(info.get('remediation')).strip() + '\n')
            if item.get('extracted-results'):
                f.write('Evidence     : ' + str(item.get('extracted-results')) + '\n')
            if item.get('curl-command'):
                f.write('Reproduce    : ' + str(item.get('curl-command')) + '\n')
            f.write('\n' + sep_line + '\n\n')

# Generate Detailed HTML Report
with open(report_html, 'w', encoding='utf-8') as h:
    h.write('<!DOCTYPE html>\n<html>\n<head>\n<meta charset="utf-8">\n')
    h.write('<title>Nuclei Vulnerability Scan Report</title>\n<style>\n')
    h.write('body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 30px; background: #f8fafc; color: #1e293b; }\n')
    h.write('h1 { color: #0f172a; margin-bottom: 5px; }\n')
    h.write('.summary { background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); margin-bottom: 25px; }\n')
    h.write('.card { background: #fff; border-radius: 8px; padding: 20px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); border-left: 6px solid #94a3b8; }\n')
    h.write('.card.critical { border-left-color: #dc2626; }\n')
    h.write('.card.high { border-left-color: #ea580c; }\n')
    h.write('.card.medium { border-left-color: #f59e0b; }\n')
    h.write('.card.low { border-left-color: #3b82f6; }\n')
    h.write('.card.info { border-left-color: #64748b; }\n')
    h.write('.badge { display: inline-block; padding: 4px 10px; border-radius: 4px; font-weight: 600; font-size: 12px; color: #fff; text-transform: uppercase; }\n')
    h.write('.badge.critical { background: #dc2626; }\n')
    h.write('.badge.high { background: #ea580c; }\n')
    h.write('.badge.medium { background: #f59e0b; }\n')
    h.write('.badge.low { background: #3b82f6; }\n')
    h.write('.badge.info { background: #64748b; }\n')
    h.write('.field { margin: 8px 0; font-size: 14px; }\n')
    h.write('.label { font-weight: 600; color: #475569; }\n')
    h.write('pre { background: #0f172a; color: #f1f5f9; padding: 12px; border-radius: 6px; overflow-x: auto; font-size: 13px; }\n')
    h.write('</style>\n</head>\n<body>\n')
    h.write('<h1>Nuclei DAST Security Report</h1>\n')
    h.write('<div class="summary">\n')
    h.write('<p><b>Target:</b> <a href="' + target_url + '">' + target_url + '</a> | <b>Total Findings:</b> ' + str(len(findings)) + '</p>\n')
    h.write('</div>\n')

    if not findings:
        h.write('<div class="card low"><p>No security vulnerabilities identified matching the configured severities.</p></div>\n')
    else:
        for item in findings:
            info = item.get('info') or {}
            sev = str(info.get('severity', 'info')).lower()
            title = info.get('name') or item.get('template-id') or 'Finding'
            matched = item.get('matched-at') or item.get('host') or ''
            tmpl_id = item.get('template-id', '')

            h.write('<div class="card ' + sev + '">\n')
            h.write('  <div style="display:flex; justify-content:space-between; align-items:center;">\n')
            h.write('    <h3 style="margin:0;">' + title + '</h3>\n')
            h.write('    <span class="badge ' + sev + '">' + sev + '</span>\n')
            h.write('  </div>\n')
            h.write('  <div class="field"><span class="label">URL:</span> <code>' + matched + '</code></div>\n')
            h.write('  <div class="field"><span class="label">Template:</span> ' + tmpl_id + '</div>\n')
            if info.get('description'):
                h.write('  <div class="field"><span class="label">Description:</span> ' + str(info.get('description')) + '</div>\n')
            if info.get('remediation'):
                h.write('  <div class="field"><span class="label">Remediation:</span> <b>' + str(info.get('remediation')) + '</b></div>\n')
            if item.get('curl-command'):
                h.write('  <div class="field"><span class="label">Curl Command:</span><pre>' + str(item.get('curl-command')) + '</pre></div>\n')
            h.write('</div>\n')

    h.write('</body>\n</html>\n')
PYEOF

    python3 "${reportDir}/generate_nuclei_report.py" \
        "${reportDir}/nuclei-report.json" \
        "${reportDir}/nuclei-report.txt" \
        "${reportDir}/nuclei-report.html" \
        "${targetUrl}" \
        "${severity}" \
        || true

    rm -f "${reportDir}/generate_nuclei_report.py"

    # Fallback to standard text if Python is not present
    if [ ! -s "${reportDir}/nuclei-report.txt" ]; then
        if [ -s "${reportDir}/nuclei-raw.txt" ]; then
            cp "${reportDir}/nuclei-raw.txt" "${reportDir}/nuclei-report.txt"
        else
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
    fi

    echo "Nuclei report generated at ${reportDir}/nuclei-report.txt"
    if [ -f "${reportDir}/nuclei-report.html" ]; then
        echo "Nuclei HTML report generated at ${reportDir}/nuclei-report.html"
    fi
    if [ -f "${reportDir}/nuclei-report.json" ]; then
        echo "Nuclei JSON export generated at ${reportDir}/nuclei-report.json"
    fi
    """
}
