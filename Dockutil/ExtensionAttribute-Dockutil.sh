#!/bin/sh
# Check to see if dockutil exists
if [ -f /usr/local/bin/dockutil ]; then
  echo "true"
else
  echo "false"
fi

exit 0
