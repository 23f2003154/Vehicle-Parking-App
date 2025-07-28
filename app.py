from flask import Flask,render_template,request,redirect,url_for,flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

app = Flask(__name__)


@app.context_processor
def inject_now():
    return {'now': lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

import config

import models

import routes