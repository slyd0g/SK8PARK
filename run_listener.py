from flask import Flask
from flask_restful import Api
from flask_sqlalchemy import SQLAlchemy


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'myreallylongsecretkeypassword_'

db = SQLAlchemy(app)

import resources_listener  # noqa: E402

api = Api(app)
api.add_resource(resources_listener.NegotiateSessionKey, '/stage0')
api.add_resource(resources_listener.ChallengeResponseOne, '/stage1')
api.add_resource(resources_listener.ChallengeResponseTwo, '/stage2')
api.add_resource(resources_listener.FirstCheckIn, '/stage3')
api.add_resource(resources_listener.SK8RATGet, '/get')
api.add_resource(resources_listener.SK8RATPost, '/post')


@app.before_first_request
def create_tables():
    db.create_all()
