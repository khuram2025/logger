#!/bin/bash

# Change to the analyzer directory
cd /home/net/analyzer

# Activate virtual environment
source device-manager-env/bin/activate

# Collect static files (in case of updates)
python manage.py collectstatic --noinput --clear

# Start Gunicorn
exec gunicorn --config gunicorn.conf.py fwanalyzer.wsgi:application