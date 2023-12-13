#!/bin/bash

# Start chrony
chronyd -d &

# Start the app
/app/waas-auth

# Wait for any process to exit
wait -n

# Exit with status of process that exited first
exit $?

