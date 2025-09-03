from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class Ioc(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    indicator = db.Column(db.String(256), nullable=False)
    type = db.Column(db.String(64), nullable=False)
    description = db.Column(db.String(256))
    tags = db.Column(db.PickleType)  # stores Python list of tags
    threat_level = db.Column(db.String(32))
    source = db.Column(db.String(64))
    date = db.Column(db.DateTime, default=datetime.utcnow)
