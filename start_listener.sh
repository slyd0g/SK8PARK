#!/bin/sh
port="$1"
FLASK_APP=run_listener.py flask run --host=0.0.0.0 --port $1
