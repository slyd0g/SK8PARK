#!/bin/sh
port="$1"
FLASK_APP=run2.py flask run --host=0.0.0.0 --port $1
