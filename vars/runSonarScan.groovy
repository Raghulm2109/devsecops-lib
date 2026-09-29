#!/usr/bin/env groovy

/**
 * vars/runSonarScan.groovy
 * Executes SonarQube Scanner Analysis dynamically across Dev, Stage, and Prod nodes.
 * Auto-detects Java 17, Sonar Scanner (CLI or JAR), and sonar-project.properties.
 *
 * Usage:
 *   runSonarScan(
 *       projectKey: 'Ezyprocure-stage',
 *       projectName: 'Ezyprocure-stage',
 *       credentialsId: 'sonar-token',
 *       sonarHostUrl: 'http://10.9.3.15:9000'
 *   )
 */
def call(Map config = [:]) {
    String projectKey    = config.projectKey ?: 'Ezyprocure-Development'
    String projectName   = config.projectName ?: projectKey
    String credentialsId = config.credentialsId ?: 'sonar-token'
    String sonarHostUrl  = config.sonarHostUrl ?: 'http://10.9.3.15:9000'
    String settingsFile  = config.settingsFile ?: ''
    String scannerJar    = config.scannerJar ?: ''
    String javaBin       = config.javaBin ?: ''

    echo "============================================================"
    echo "  [DevSecOps] Executing SonarQube Scanner"
    echo "  Project: ${projectKey}"
    echo "  Sonar Server: ${sonarHostUrl}"
    echo "============================================================"

    withCredentials([string(credentialsId: credentialsId, variable: 'SONAR_TOKEN')]) {
        sh """
        # 1. Detect Java 17 or fallback to system Java
        JAVA_EXEC=""
        if [ -n "${javaBin}" ] && [ -x "${javaBin}" ]; then
            JAVA_EXEC="${javaBin}"
        else
            for cand in \
                /usr/lib/jvm/java-17-openjdk-amd64/bin/java \
                /usr/lib/jvm/java-17*/bin/java \
                /usr/lib/jvm/java-11-openjdk-amd64/bin/java \
                /usr/lib/jvm/java-11*/bin/java \
                \$(which java 2>/dev/null) \
                \$(command -v java 2>/dev/null); do
                if [ -x "\$cand" ]; then
                    JAVA_EXEC="\$cand"
                    break
                fi
            done
        fi
        echo "Using Java binary: \${JAVA_EXEC:-\$(which java)}"

        # 2. Locate or auto-detect sonar-project.properties
        SETTINGS_PATH=""
        if [ -n "${settingsFile}" ] && [ -f "${settingsFile}" ]; then
            SETTINGS_PATH="${settingsFile}"
        elif [ -f "./sonar-project.properties" ]; then
            SETTINGS_PATH="./sonar-project.properties"
        elif [ -f "\$HOME/sonar-project.properties" ]; then
            SETTINGS_PATH="\$HOME/sonar-project.properties"
        else
            EXISTING_PROPS=\$(find /home -maxdepth 2 -name "sonar-project.properties" 2>/dev/null | head -n 1)
            if [ -n "\$EXISTING_PROPS" ] && [ -f "\$EXISTING_PROPS" ]; then
                SETTINGS_PATH="\$EXISTING_PROPS"
            else
                echo "Creating dynamic sonar-project.properties fallback..."
                SETTINGS_PATH="/tmp/sonar-project.properties"
                SRC_DIR="src"
                [ ! -d "\$SRC_DIR" ] && SRC_DIR="."
                BIN_DIR="target/classes"
                [ ! -d "\$BIN_DIR" ] && BIN_DIR="target"
                [ ! -d "\$BIN_DIR" ] && BIN_DIR="."
                cat << EOF > /tmp/sonar-project.properties
sonar.sources=\$SRC_DIR
sonar.java.binaries=\$BIN_DIR
sonar.sourceEncoding=UTF-8
EOF
            fi
        fi
        echo "Using Sonar properties: \$SETTINGS_PATH"

        # 3. Locate Sonar Scanner CLI binary or JAR
        SCANNER_CLI=""
        SCANNER_JAR=""

        if command -v sonar-scanner >/dev/null 2>&1; then
            SCANNER_CLI="\$(command -v sonar-scanner)"
        fi

        if [ -z "\$SCANNER_CLI" ]; then
            for cand_jar in \
                "${scannerJar}" \
                "\$HOME/sonar-scanner-4.6.2.2472-linux/lib/sonar-scanner-cli-4.6.2.2472.jar" \
                "\$HOME"/sonar-scanner*/lib/sonar-scanner-cli*.jar \
                /opt/sonar-scanner*/lib/sonar-scanner-cli*.jar \
                /home/*/sonar-scanner*/lib/sonar-scanner-cli*.jar \
                /usr/local/sonar-scanner*/lib/sonar-scanner-cli*.jar; do
                if [ -n "\$cand_jar" ] && [ -f "\$cand_jar" ]; then
                    SCANNER_JAR="\$cand_jar"
                    break
                fi
            done
        fi

        if [ -z "\$SCANNER_CLI" ] && [ -z "\$SCANNER_JAR" ]; then
            for cand_bin in \
                "\$HOME/sonar-scanner-4.6.2.2472-linux/bin/sonar-scanner" \
                "\$HOME"/sonar-scanner*/bin/sonar-scanner \
                /opt/sonar-scanner*/bin/sonar-scanner \
                /home/*/sonar-scanner*/bin/sonar-scanner; do
                if [ -n "\$cand_bin" ] && [ -x "\$cand_bin" ]; then
                    SCANNER_CLI="\$cand_bin"
                    break
                fi
            done
        fi

        # 4. Auto-download Sonar Scanner CLI if missing on node
        if [ -z "\$SCANNER_CLI" ] && [ -z "\$SCANNER_JAR" ]; then
            echo "SonarQube scanner not found on node. Auto-downloading Sonar Scanner 4.6.2..."
            mkdir -p /tmp/sonar-scanner
            if [ ! -f /tmp/sonar-scanner/sonar-scanner-4.6.2.2472-linux/lib/sonar-scanner-cli-4.6.2.2472.jar ]; then
                curl -sS -L -o /tmp/sonar-scanner.zip \
                    "https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/sonar-scanner-cli-4.6.2.2472-linux.zip"
                unzip -q -o /tmp/sonar-scanner.zip -d /tmp/sonar-scanner
                rm -f /tmp/sonar-scanner.zip
            fi
            SCANNER_JAR="/tmp/sonar-scanner/sonar-scanner-4.6.2.2472-linux/lib/sonar-scanner-cli-4.6.2.2472.jar"
            SCANNER_CLI="/tmp/sonar-scanner/sonar-scanner-4.6.2.2472-linux/bin/sonar-scanner"
        fi

        # 5. Execute SonarQube Analysis
        mkdir -p /tmp/.scannerwork
        if [ -n "\$SCANNER_CLI" ] && [ -x "\$SCANNER_CLI" ]; then
            echo "Executing SonarQube Scanner via CLI binary: \$SCANNER_CLI"
            "\$SCANNER_CLI" \
                -Dproject.settings="\$SETTINGS_PATH" \
                -Dsonar.working.directory=/tmp/.scannerwork \
                -Dsonar.host.url="${sonarHostUrl}" \
                -Dsonar.token="\$SONAR_TOKEN" \
                -Dsonar.login="\$SONAR_TOKEN" \
                -Dsonar.projectName="${projectName}" \
                -Dsonar.projectKey="${projectKey}" || true
        elif [ -n "\$SCANNER_JAR" ] && [ -f "\$SCANNER_JAR" ]; then
            echo "Executing SonarQube Scanner via JAR: \$SCANNER_JAR using Java: \$JAVA_EXEC"
            "\$JAVA_EXEC" -jar "\$SCANNER_JAR" \
                -Dproject.settings="\$SETTINGS_PATH" \
                -Dsonar.working.directory=/tmp/.scannerwork \
                -Dsonar.host.url="${sonarHostUrl}" \
                -Dsonar.token="\$SONAR_TOKEN" \
                -Dsonar.login="\$SONAR_TOKEN" \
                -Dsonar.projectName="${projectName}" \
                -Dsonar.projectKey="${projectKey}" || true
        else
            echo "ERROR: Unable to locate or run SonarQube Scanner."
        fi

        rm -rf /tmp/.scannerwork
        """
    }
}
