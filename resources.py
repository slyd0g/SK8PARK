from flask_restful import Resource, reqparse
from flask import request
from models import (UserModel, RevokedTokenModel, ListenerModel,
                    TaskModel, SK8RATModel)
from flask_jwt_extended import (create_access_token, create_refresh_token,
                                jwt_required, jwt_refresh_token_required,
                                get_jwt_identity, get_raw_jwt)
import nacl.secret
import nacl.utils
from nacl.public import PrivateKey, SealedBox
from nacl import encoding
import base64
import random
import string
import json
import subprocess


parser = reqparse.RequestParser()
parser.add_argument('username',
                    help='This field cannot be blank',
                    required=True
                    )
parser.add_argument('password',
                    help='This field cannot be blank',
                    required=True
                    )


#  /api/version
class Version(Resource):
    @jwt_required
    def get(self):
        return {'version': '1.0'}


#  /api/admin/login
class AdminLogin(Resource):
    def post(self):
        data = parser.parse_args()
        current_user = UserModel.find_by_username(data['username'])
        if not current_user:
            return {'message':
                    'User {} doesn\'t exist'.format(data['username'])}
        if UserModel.verify_hash(data['password'], current_user.password):
            access_token = create_access_token(identity=data['username'])
            refresh_token = create_refresh_token(identity=data['username'])
            return {
                'message': 'Logged in as {}'.format(current_user.username),
                'access_token': access_token,
                'refresh_token': refresh_token
                }
        else:
            return {'message': 'Wrong credentials'}


#  /api/admin/logout/access
class AdminLogoutAccess(Resource):
    @jwt_required
    def post(self):
        jti = get_raw_jwt()['jti']
        try:
            revoked_token = RevokedTokenModel(jti=jti)
            revoked_token.add()
            return {'message': 'Access token has been revoked'}
        except Exception:
            return {'message': 'Something went wrong'}, 500


#  /api/admin/logout/refresh
class AdminLogoutRefresh(Resource):
    @jwt_refresh_token_required
    def post(self):
        jti = get_raw_jwt()['jti']
        try:
            revoked_token = RevokedTokenModel(jti=jti)
            revoked_token.add()
            return {'message': 'Refresh token has been revoked'}
        except Exception:
            return {'message': 'Something went wrong'}, 500


#  /api/admin/token/refresh
class AdminTokenRefresh(Resource):
    @jwt_refresh_token_required
    def post(self):
        current_user = get_jwt_identity()
        access_token = create_access_token(identity=current_user)
        return {'access_token': access_token}


#  /api/admin/users
class AdminUsers(Resource):
    @jwt_required
    def get(self):
        return UserModel.return_all()

    @jwt_required
    def delete(self):
        return UserModel.delete_all()

    @jwt_required
    def post(self):
        data = parser.parse_args()
        if UserModel.find_by_username(data['username']):
            return {'message':
                    'User {} already exists'.format(data['username'])}
        new_user = UserModel(
            username=data['username'],
            password=UserModel.generate_hash(data['password'])
        )
        try:
            new_user.save_to_db()
            access_token = create_access_token(identity=data['username'])
            refresh_token = create_refresh_token(identity=data['username'])
            return {
                'message': 'User {} was created'.format(data['username']),
                'access_token': access_token,
                'refresh_token': refresh_token
                }
        except Exception:
            return {'message': 'Something went wrong'}, 500


#  /api/listeners/http
class CreateListener(Resource):
    #  @jwt_required
    def post(self):
        if not request.is_json:
            return {'message': 'Invalid JSON object'}

        # Make sure only 1 listener exists
        Listener = ListenerModel.query.filter(ListenerModel.listener_type == "http").first()
        if Listener:
            return {'message': 'Http listener already exists.'}

        content = request.get_json()
        # Generate shared key
        sharedkey = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
        sharedkey_b64 = base64.b64encode(sharedkey).decode("UTF-8")
        new_listener = ListenerModel(
            name=content['name'],
            description="SK8RATs http listener",
            ip=content['ip'],
            port=content['port'],
            listener_type="http",
            shared_key=sharedkey_b64
        )
        new_listener.save_to_db()
   
        # Start listener
        port = str(new_listener.port)
        subprocess.Popen(["./start_listener.sh", port])

        return {'message': 'Listener created'}


#  /api/listeners
class AllListeners(Resource):
    #  @jwt_required
    def get(self):
        return ListenerModel.return_all()

    #  @jwt_required
    def delete(self):
        return ListenerModel.delete_all()


#  /api/listeners/<name>
class SingleListener(Resource):
    #  @jwt_required
    def get(self, listener_name):
        return ListenerModel.return_single(listener_name)

    #  @jwt_required
    def delete(self, listener_name):
        return ListenerModel.delete_single(listener_name)


#  /api/listeners/options/<listener type>
class OptionsListener(Resource):
    @jwt_required
    def get(self):
        return "TO-DO (return listener options)"


#  /api/SK8RATs
class AllSK8RATs(Resource):
    #  @jwt_required
    def get(self):
        return SK8RATModel.return_all()

    #  @jwt_required
    def delete(self):
        return SK8RATModel.delete_all()


#  /api/SK8RATs/<name>
class SingleSK8RAT(Resource):
    #  @jwt_required
    def get(self, SK8RAT_name):
        return SK8RATModel.return_single(SK8RAT_name)

    #  @jwt_required
    def delete(self, SK8RAT_name):
        return SK8RATModel.delete_single(SK8RAT_name)

    #  @jwt_required
    def post(self, SK8RAT_name):
        # Get raw request and read as json blob
        request_raw = request.data.decode("UTF-8")
        json_blob = json.loads(request_raw)
       
        # Update name, sleep and jitter
        SK8RAT = SK8RATModel.query.filter(SK8RATModel.name == SK8RAT_name).first()
        if (json_blob['name'] != ""):
            SK8RAT.name = json_blob['name']
        if (json_blob['sleep'] != ""):
            SK8RAT.sleep = json_blob['sleep']
        if (json_blob['jitter'] != ""):
            SK8RAT.jitter = json_blob['jitter']
        SK8RAT.save_to_db()

        return {'message': 'Success'}


#  /api/tasks/<name>, accepts {"task":"<tasking>"}
class TaskSK8RAT(Resource):
    #  @jwt_required
    def post(self, SK8RAT_name):
        # Get raw request and read as json blob
        request_raw = request.data.decode("UTF-8")
        json_blob = json.loads(request_raw)

        # Check SK8RAT by name
        SK8RAT = SK8RATModel.query.filter(SK8RATModel.name == SK8RAT_name).first()

        # If name doesn't exist, error; else grab guid
        if (not SK8RAT):
            return {'message': 'SK8RAT does not exist.'}
        guid = SK8RAT.guid

        # Check guid against tasking database
        task = TaskModel.query.filter(TaskModel.guid == guid).first()

        if (task is None):
            # task was not found, create initial
            new_task = TaskModel(
                guid=guid,
                task_id=1,
                task=json_blob['task'],
                task_status="wait",
                task_output=""
            )
        else:
            # task was found, find most recent task_id for this guid, add 1
            task2 = TaskModel.query.filter(TaskModel.guid == guid).order_by(TaskModel.task_id.desc()).first()       
            new_task = TaskModel(
                guid=guid,
                task_id=task2.task_id + 1,
                task=json_blob['task'],
                task_status="wait",
                task_output=""
            )
        
        new_task.save_to_db()
        message = "Task " + json_blob['task'] + " with task id " + str(new_task.task_id) +\
                  " assigned to " + SK8RAT.name + "."
        return {'message': message}

    #  @jwt_required
    def get(self, SK8RAT_name):
        # Check SK8RAT by name
        SK8RAT = SK8RATModel.query.filter(SK8RATModel.name == SK8RAT_name).first()
        # If name doesn't exist, error; else grab guid
        if (not SK8RAT):
            return {'message': 'SK8RAT does not exist.'}
        guid = SK8RAT.guid
        return TaskModel.return_single(guid)


#  /api/tasks/
class TaskAllSK8RAT(Resource):
    #  @jwt_required
    def get(self):
        return TaskModel.return_all()
  
    #  @jwt_required
    def delete(self):
        return TaskModel.delete_all()

