trap "trap - SIGTERM && kill -- -$$" SIGINT SIGTERM EXIT
#trap 'kill $BGPID; exit' INT
export FLASK_APP=run.py; flask run --host=0.0.0.0 &
BGPID=$!
cd react-sk8park; npm start 
