#!/bin/sh
ExtensionVersion=""
if [ -f /usr/local/bin/dockutil ]; then
	ExtensionVersion=$(pkgutil --pkg-info dockutil.cli.tool | grep version | awk '{ print $2 }')
fi

echo "<result>$ExtensionVersion</result>"

exit 0
