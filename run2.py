from flask import Flask
from flask_restful import Api
from flask_sqlalchemy import SQLAlchemy


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'myreallylongsecretkeypassword_'

db = SQLAlchemy(app)

import resources2  # noqa: E402
import models2  # noqa: E402

api = Api(app)
api.add_resource(resources2.NegotiateSessionKey, '/stage0')
api.add_resource(resources2.ChallengeResponseOne, '/stage1')
api.add_resource(resources2.ChallengeResponseTwo, '/stage2')
api.add_resource(resources2.FirstCheckIn, '/stage3')
api.add_resource(resources2.Beaconing, '/beaconing')


@app.before_first_request
def create_tables():
    db.create_all()
