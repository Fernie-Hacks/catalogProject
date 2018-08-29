from models import Base, User, Category, Item
from flask import Flask, jsonify, request, url_for, g, render_template, abort, flash
from flask_bootstrap import Bootstrap
#from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine

from flask_httpauth import HTTPBasicAuth
from flask import session as login_session
import json
from werkzeug.utils import redirect
from posix import abort

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
def index():
    categories = session.query(Category).order_by(Category.id).all()
    items = session.query(Item).order_by(Item.id.desc()).limit(9).all()
    if 'username' not in login_session:
        return render_template('test.html', categories = categories, items = items)
    else:
        return render_template('index.html', categories = categories, items = items)
    
@app.route('/SignUpUser', methods=['POST'])
def newUser():
    # Create a new user via username / password instead of incorporating a provider
    username = request.json.get('username')
    password = request.json.get('password')
    if username is None or password is None:
        # Missing information in order to create user <import  abourt>?
        abort(400) 
        flash('Password or username missing!')
        return redirect('/login')
    user = User(name = username)
    user.hash_password(password)
    session.add(user)
    session.commit()
 
@app.route('/login')    
def login():
    return render_template('login.html')

@app.route("/<string:category_name>/items")
def showCategoryItems(category_name):
    category = session.query(Category).filter_by(name = category_name).one()
    categories = session.query(Category).order_by(Category.id).all()
    items = session.query(Item).filter_by(cat_id = category.id).all()
    return render_template('showCategoryItems.html', categories = categories, items = items)

@app.route("/<string:category_name>/<string:item_name>")
def showItemDescription(category_name, item_name):
    category = session.query(Category).filter_by(name = category_name).one()
    item = session.query(Item).filter_by(cat_id = category.id).all().filter_by(name = item_name).one()
    return render_template('showItemDescription.html', item = item)

@app.route("/<string:category_name>/new", methods=['GET','POST'])
def newItem(category_name):
    if 'username' not in login_session:
        return redirect('/')
    else:
        pass

@app.route("/<string:category_name>/<string:item_name>/edit", methods=['GET','POST'])
def editItem(category_name, item_name):
    if 'username' not in login_session:
        return redirect('/')
    else:
        pass
    
@app.route("/<string:category_name>/<string:item_name>/delete", methods=['GET','POST'])
def deleteItem(category_name, item_name):
    if 'username' not in login_session:
        return redirect('/')
    else:
        pass

# In order to be able to distinguish this when running as the main program ex 'python views.py'
# *** When using this method python will set __name__ to have a value of '__main__' by default
# Or when someone import this module and uses functions form here, when using the this option
# *** Python interpreter sets the __name__ variable to the module name instead of main  
if __name__ == '__main__':
    app.debug = True
    app.run(host='0.0.0.0', port=8000)