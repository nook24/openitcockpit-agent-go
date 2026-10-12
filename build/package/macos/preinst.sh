#!/bin/zsh
# preinst.sh - Pre-Installation Script for openITCOCKPIT Agent on macOS

# Configuration
OLD_LABEL="com.it-novum.openitcockpit.agent"
NEW_LABEL="io.openitcockpit.agent"
AGENT_DIR="/Applications/openitcockpit-agent"

# Function to cleanly remove a service
remove_service() {
    local label=$1
    local plist="/Library/LaunchDaemons/${label}.plist"

    if /bin/launchctl list | grep -q "$label"; then
        # Modern macOS 15 bootout (stops and unloads)
        /bin/launchctl bootout system "$plist" 2>/dev/null
        # Legacy Fallback
        /bin/launchctl unload -F "$plist" 2>/dev/null
    fi

    # Delete plist at system location
    rm -f "$plist"
}

# 1. Remove both possible services (ensure migration)
remove_service "$OLD_LABEL"
remove_service "$NEW_LABEL"

# Delete old plist file
if [ -f "$OLD_PLIST" ]; then
    rm -f "$OLD_PLIST"
fi

# Backup configurations to prevent overwriting
# We append .old to safely identify them in postinstall
for cfg in config.ini customchecks.ini prometheus_exporters.ini logfiles.ini certificates.ini files.ini http.ini; do
    if [ -f "$AGENT_DIR/$cfg" ]; then
        cp "$AGENT_DIR/$cfg" "$AGENT_DIR/$cfg.old"
    fi
done

exit 0