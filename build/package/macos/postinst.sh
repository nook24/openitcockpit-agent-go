#!/bin/zsh
# postinst.sh - Post-Installation Script for openITCOCKPIT Agent on macOS

# Configuration
AGENT_DIR="/Applications/openitcockpit-agent"
NEW_LABEL="io.openitcockpit.agent"
NEW_PLIST_NAME="$NEW_LABEL.plist"
PLIST_DEST="/Library/LaunchDaemons/$NEW_PLIST_NAME"
LOG_DIR="/Library/Logs/openitcockpit-agent"

# Set permissions for the program directory
chown root:wheel "$AGENT_DIR/openitcockpit-agent"
chmod 755 "$AGENT_DIR/openitcockpit-agent"

# Copy new plist to destination & secure it
if [ -f "$AGENT_DIR/$NEW_PLIST_NAME" ]; then
    cp "$AGENT_DIR/$NEW_PLIST_NAME" "$PLIST_DEST"
    chown root:wheel "$PLIST_DEST"
    chmod 644 "$PLIST_DEST"
fi

# Prepare log directory
mkdir -p "$LOG_DIR"
chmod 755 "$LOG_DIR"

# Restore configurations from backup (if available)
for cfg in config.ini customchecks.ini prometheus_exporters.ini logfiles.ini; do
    if [ -f "$AGENT_DIR/$cfg.old" ]; then
        cp "$AGENT_DIR/$cfg.old" "$AGENT_DIR/$cfg"
    fi
done

# Register the new service using modern methods (macOS 15 compatible)
# First, safely bootout in case a previous version of the new label was running
/bin/launchctl bootout system "$PLIST_DEST" 2>/dev/null

# Enable and load the service
/bin/launchctl bootstrap system "$PLIST_DEST"

# Explicitly start the service
/bin/launchctl kickstart -k system/"$NEW_LABEL"

exit 0