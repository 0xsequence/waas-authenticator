#!/bin/bash

# Start chrony
chronyd -d &

# Start the app
/app/waas-auth

# Wait for any process to exit
wait -n

# Stay alive, makes it easier to debug
sleep 2073600

