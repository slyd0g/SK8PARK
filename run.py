from flask import Flask
from flask_restful import Api
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'myreallylongsecretkeypassword_'
app.config['JWT_SECRET_KEY'] = 'myreallylongjwtsecretkeypassword'
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']
app.config['JWT_TOKEN_LOCATION'] = 'query_string'
app.config['JWT_QUERY_STRING_NAME'] = 'token'

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
api.add_resource(resources.NegotiateSessionKey, '/stage0')
api.add_resource(resources.ChallengeResponseOne, '/stage1')
api.add_resource(resources.ChallengeResponseTwo, '/stage2')
api.add_resource(resources.FirstCheckIn, '/stage3')
api.add_resource(resources.Beaconing, '/beaconing')


# DEBUG ONLY
api.add_resource(resources.sessiontest1, '/sessiontest1')
api.add_resource(resources.sessiontest2, '/sessiontest2')


@app.before_first_request
def create_tables():
    db.create_all()


@jwt.token_in_blacklist_loader
def check_if_token_in_blacklist(decrypted_token):
    jti = decrypted_token['jti']
    return models.RevokedTokenModel.is_jti_blacklisted(jti)
