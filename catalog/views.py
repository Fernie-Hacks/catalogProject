from models import Base, User
from flask import Flask, jsonify, request, url_for, g, render_template #, abort
from flask_bootstrap import Bootstrap
#from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine

from flask_httpauth import HTTPBasicAuth
import json

auth = HTTPBasicAuth()

engine = create_engine('sqlite:///catalog.db', connect_args={'check_same_thread': False})

# Create a "bound" between the DB Table (catalog) and the engine
# This allows SQL statements access to execute method and all other SQL constructs.
Base.metadata.bind = engine
# Create a reference to the sessionmaker class.
DBSession = sessionmaker
session = DBSession()
app = Flask(__name__)
#Pass flask application to bootstrap
Bootstrap(app)

CLIENT_ID = json.loads(open('client_secrets.json', 'r').read())['web']['client_id']

@app.route('/')
@app.route("/test", methods = ['GET', 'POST'])
def index():
    return render_template('test.html')

# In order to be able to distinguish this when running as the main program ex 'python views.py'
# *** When using this method python will set __name__ to have a value of '__main__' by default
# Or when someone import this module and uses functions form here, when using the this option
# *** Python interpreter sets the __name__ variable to the module name instead of main  
if __name__ == '__main__':
    app.debug = True
    app.run(host='0.0.0.0', port=8000)