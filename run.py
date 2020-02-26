from flask import Flask
from flask_restful import Api
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_cors import CORS
import subprocess
import sqlalchemy_utils

app = Flask(__name__)
CORS(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'myreallylongsecretkeypassword_'
app.config['JWT_SECRET_KEY'] = 'myreallylongjwtsecretkeypassword'
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = 604800 # 1 week 300  # 5 minutes, back end auths every minute
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = 604800  # 1 week
app.config['JWT_TOKEN_LOCATION'] = 'headers'
app.config['JWT_HEADER_NAME'] = 'CustomAuthorization'

db = SQLAlchemy(app)
jwt = JWTManager(app)

import resources  # noqa: E402
import models  # noqa: E402

api = Api(app)
api.add_resource(resources.AdminLogin, '/api/admin/login')
api.add_resource(resources.AdminLogoutAccess, '/api/admin/logout/access')
api.add_resource(resources.AdminLogoutRefresh, '/api/admin/logout/refresh')
api.add_resource(resources.AdminTokenRefresh, '/api/admin/token/refresh')
api.add_resource(resources.AdminUsers, '/api/admin/users')
api.add_resource(resources.Version, '/api/version')
api.add_resource(resources.CreateListener, '/api/listeners/http')
api.add_resource(resources.AllListeners, '/api/listeners')
api.add_resource(resources.SingleListener, '/api/listeners/<listener_name>')
api.add_resource(resources.AllSK8RATs, '/api/SK8RATs')
api.add_resource(resources.SingleSK8RAT, '/api/SK8RATs/<SK8RAT_name>')
api.add_resource(resources.TaskSK8RAT, '/api/tasks/<SK8RAT_name>')
api.add_resource(resources.TaskAllSK8RAT, '/api/tasks')

if not sqlalchemy_utils.database_exists('sqlite:///app.db'):
    db.create_all()

# Check for existing database, then check for existing listener
if sqlalchemy_utils.database_exists('sqlite:///app.db'):
    Listener = models.ListenerModel.query.filter(models.ListenerModel.listener_type == "http").first()
    if Listener:
        port = str(Listener.port)
        subprocess.Popen(["./start_listener.sh", port])

# Check that admin user exists
admin_user = models.UserModel.query.filter(models.UserModel.username == "sk8park_admin").first()
if not admin_user:
    create_admin = models.UserModel(
            username="sk8park_admin",
            password=models.UserModel.generate_hash("sk8park_admin")
        )
    create_admin.save_to_db()


@jwt.token_in_blacklist_loader
def check_if_token_in_blacklist(decrypted_token):
    jti = decrypted_token['jti']
    return models.RevokedTokenModel.is_jti_blacklisted(jti)
