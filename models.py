from run import db
from passlib.hash import pbkdf2_sha256 as sha256


class UserModel(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    @classmethod
    def find_by_username(cls, username):
        return cls.query.filter_by(username=username).first()

    @classmethod
    def return_all(cls):
        def to_json(x):
            return {
                'username': x.username,
                'password': x.password
            }
        return {'users': list(map(lambda x: to_json(x),
                UserModel.query.all()))}

    @classmethod
    def delete_all(cls):
        try:
            num_rows_deleted = db.session.query(cls).delete()
            db.session.commit()
            return {'message': '{} row(s) deleted'.format(num_rows_deleted)}
        except Exception:
            return {'message': 'Something went wrong'}

    @staticmethod
    def generate_hash(password):
        return sha256.hash(password)

    @staticmethod
    def verify_hash(password, hash):
        return sha256.verify(password, hash)


class RevokedTokenModel(db.Model):
    __tablename__ = 'revoked_tokens'
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(120))

    def add(self):
        db.session.add(self)
        db.session.commit()

    @classmethod
    def is_jti_blacklisted(cls, jti):
        query = cls.query.filter_by(jti=jti).first()
        return bool(query)


class SK8RATModel(db.Model):
    __tablename__ = 'SK8RATs'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=True)
    guid = db.Column(db.String(120), nullable=True)
    username = db.Column(db.String(120), nullable=True)
    hostname = db.Column(db.String(120), nullable=True)
    pid = db.Column(db.Integer, nullable=True)
    internal_ip = db.Column(db.String(120), nullable=True)
    external_ip = db.Column(db.String(120), nullable=True)
    admin = db.Column(db.Boolean, nullable=True)
    os = db.Column(db.String(120), nullable=True)
    listener_id = db.Column(db.Integer, nullable=True)
    server_ip = db.Column(db.String(120), nullable=True)
    sleep = db.Column(db.Integer, nullable=True)
    jitter = db.Column(db.Integer, nullable=True)
    session_key = db.Column(db.String(120), nullable=True)
    client_challenge = db.Column(db.String(120), nullable=True)
    server_challenge = db.Column(db.String(120), nullable=True)
    session_cookie = db.Column(db.String(120), nullable=True)
    last_seen = db.Column(db.String(120), nullable=True)

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    @classmethod
    def return_all(cls):
        def to_json(x):
            return {
                'id': x.id,
                'name': x.name,
                'guid': x.guid,
                'username': x.username,
                'hostname': x.hostname,
                'pid': x.pid,
                'internal_ip': x.internal_ip,
                'external_ip': x.external_ip,
                'admin': x.admin,
                'os': x.os,
                'listener_id': x.listener_id,
                'server_ip': x.server_ip,
                'sleep': x.sleep,
                'jitter': x.jitter,
                'session_key': x.session_key,
                'client_challenge': x.client_challenge,
                'server_challenge': x.server_challenge,
                'session_cookie': x.session_cookie,
                'last_seen': x.last_seen,
            }
        return {'SK8RATs': list(map(lambda x: to_json(x),
                SK8RATModel.query.all()))}

    @classmethod
    def return_single(cls, SK8RAT_name):
        def to_json(x):
            return {
                'id': x.id,
                'name': x.name,
                'guid': x.guid,
                'username': x.username,
                'hostname': x.hostname,
                'pid': x.pid,
                'internal_ip': x.internal_ip,
                'external_ip': x.external_ip,
                'admin': x.admin,
                'os': x.os,
                'listener_id': x.listener_id,
                'server_ip': x.server_ip,
                'sleep': x.sleep,
                'jitter': x.jitter,
                'session_key': x.session_key,
                'client_challenge': x.client_challenge,
                'server_challenge': x.server_challenge,
                'session_cookie': x.session_cookie,
                'last_seen': x.last_seen,
            }
        SK8RAT = SK8RATModel.query.filter(SK8RATModel.name == SK8RAT_name).one_or_none()
        if SK8RAT is not None:
            return to_json(SK8RAT)
        else:
            return {'message': 'SK8RAT does not exist'}

    @classmethod
    def delete_all(cls):
        try:
            num_rows_deleted = db.session.query(cls).delete()
            db.session.commit()
            return {'message': '{} row(s) deleted'.format(num_rows_deleted)}
        except Exception:
            return {'message': 'Something went wrong'}

    @classmethod
    def delete_single(cls, SK8RAT_name):
        try:
            num_rows_deleted = SK8RATModel.query.filter(SK8RATModel.name == SK8RAT_name).delete()
            db.session.commit()
            return {'message': '{} row(s) deleted'.format(num_rows_deleted)}
        except Exception:
            return {'message': 'Something went wrong'}


class ListenerModel(db.Model):
    __tablename__ = 'listeners'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.String(120), nullable=False)
    ip = db.Column(db.String(120), nullable=False)
    port = db.Column(db.Integer, nullable=False)
    listener_type = db.Column(db.String(120), nullable=False)
    staging_key = db.Column(db.String(120), nullable=False)

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    @classmethod
    def return_all(cls):
        def to_json(x):
            return {
                'id': x.id,
                'name': x.name,
                'description': x.description,
                'ip': x.ip,
                'port': x.port,
                'listener_type': x.listener_type,
                'staging_key': x.staging_key,
            }
        return {'listeners': list(map(lambda x: to_json(x),
                ListenerModel.query.all()))}

    @classmethod
    def delete_all(cls):
        try:
            num_rows_deleted = db.session.query(cls).delete()
            db.session.commit()
            return {'message': '{} row(s) deleted'.format(num_rows_deleted)}
        except Exception:
            return {'message': 'Something went wrong'}

    @classmethod
    def return_single(cls, listener_name):
        def to_json(x):
            return {
                'id': x.id,
                'name': x.name,
                'description': x.description,
                'ip': x.ip,
                'port': x.port,
                'listener_type': x.listener_type,
                'staging_key': x.staging_key,
            }
        listener = ListenerModel.query.filter(ListenerModel.name == listener_name).one_or_none()
        if listener is not None:
            return to_json(listener)
        else:
            return {'message': 'Listener does not exist'}

    @classmethod
    def delete_single(cls, listener_name):
        try:
            num_rows_deleted = ListenerModel.query.filter(ListenerModel.name == listener_name).delete()
            db.session.commit()
            return {'message': '{} row(s) deleted'.format(num_rows_deleted)}
        except Exception:
            return {'message': 'Something went wrong'}


class TaskModel(db.Model):
    __tablename__ = 'tasks'
    id = db.Column(db.Integer, primary_key=True)
    guid = db.Column(db.String(120), nullable=True)
    task_id = db.Column(db.Integer, nullable=False)
    task = db.Column(db.String(120), nullable=False)
    task_status = db.Column(db.String(120), nullable=False)
    task_output = db.Column(db.String(120), nullable=False)

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    @classmethod
    def return_all(cls):
        def to_json(x):
            return {
                'id': x.id,
                'guid': x.guid,
                'task_id': x.task_id,
                'task': x.task,
                'task_status': x.task_status,
                'task_output': x.task_output
            }
        return {'tasks': list(map(lambda x: to_json(x),
                TaskModel.query.all()))}


    @classmethod
    def return_single(cls, SK8RAT_guid):
        def to_json(x):
            return {
                'id': x.id,
                'guid': x.guid,
                'task_id': x.task_id,
                'task': x.task,
                'task_status': x.task_status,
                'task_output': x.task_output
            }
        return {'tasks': list(map(lambda x: to_json(x),
                TaskModel.query.filter(TaskModel.guid == SK8RAT_guid).all()))}

    @classmethod
    def delete_all(cls):
        try:
            num_rows_deleted = db.session.query(cls).delete()
            db.session.commit()
            return {'message': '{} row(s) deleted'.format(num_rows_deleted)}
        except Exception:
            return {'message': 'Something went wrong'}

