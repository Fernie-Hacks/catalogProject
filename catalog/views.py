from models import Base, User, Category, Item
from flask import Flask, jsonify, request, url_for, g, render_template, abort, flash, redirect
from flask_bootstrap import Bootstrap
#from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine

from flask_httpauth import HTTPBasicAuth
from flask import session as login_session
import json
from flask.helpers import make_response

# Import needed to create flow objects, and exceptions 
from oauth2client.client import flow_from_clientsecrets # Contains OAuth parameter
from oauth2client.client import FlowExchangeError # To Catch errors during exchanges
import httplib2

app = Flask(__name__)

auth = HTTPBasicAuth()

engine = create_engine('sqlite:///catalog.db', connect_args={'check_same_thread': False})

# Create a "bound" between the DB Table (catalog) and the engine
# This allows SQL statements access to execute method and all other SQL constructs.
Base.metadata.bind = engine
# Create a reference to the sessionmaker class.
DBSession = sessionmaker(bind=engine)
session = DBSession()
#Pass flask application to bootstrap
Bootstrap(app)

# GOOGLE OAuth Application Client ID
CLIENT_ID = json.loads(open('client_secrets.json', 'r').read())['web']['client_id']

# Function used every time prior to executing another function in this project which has @auth.login_required tag. 
@auth.verify_password
def verify_password(username_or_token, password):
    user_id = User.verify_auth_token(username_or_token)
    # Check if user is using token based authentication
    if user_id:
        user = session.query(User). filter_by(id = user_id).one()
    else: 
        user = session.query(User).filter_by(username = username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True

@app.route('/token')
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token()
    return jsonify({'token': token.decode('ascii')})

@app.route('/')
def index():
    categories = session.query(Category).order_by(Category.id).all()
    items = session.query(Item).order_by(Item.id.desc()).limit(9).all()        
    if 'username' not in login_session:
        return render_template('index.html', categories = categories, items = items)
    else:
        return render_template('indexLoggedOn.html', categories = categories, items = items)
    
@app.route('/SignUpUser', methods=['POST'])
def newUser():
    # Create a new user via username / password instead of incorporating a provider
    username = request.json.get('username')
    password = request.json.get('password')
    if username is None or password is None:
        # Missing information in order to create user <import  abourt>?
        abort(400) 
        flash('Password or username missing!')
        return redirect('/SignUpUser')
    user = User(name = username)
    user.hash_password(password)
    session.add(user)
    session.commit()
 
@app.route('/login')    
def showLogin():
    return render_template('login.html')

@app.route('/oauth/<provider>', methods = ['POST'])
def providerLogin(provider):
    if provider == 'google':
        # STEP 1 - Parse the auth code
        auth_code = request.json.get('auth_code')
        # STEP 2 Exchange for a token
        try:
            # Upgrade the authorization code into a credentials object
            oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
            oauth_flow.redirect_uri = 'postmessage'
            credentials = oauth_flow.step2_exchange(auth_code)
        except FlowExchangeError:
            response = make_response(json.dumps('Failed to upgrade the authorization code'), 401)
            response.headers['Content-Type'] = 'application/json'
            return response
        
        # STEP 3 -- fIND user or make a new one
        # Get user info
        h = httplib2.Http()
        userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
        params = {'access_token': credentials.access_token, 'alt':'json'}
        answer = request.get(userinfo_url, params=params)
        
        data = answer.json()
        
        name = data['name']
        picture = data['picture']
        email = data['email']
        
        # Check if user already exists, if it doesn't make a new one
        user = session.query(User).filter_by(email=email).first()
        if not user:
            user = User(username = name, picture = picture, email = email)
            session.add(user)
            session.commit()
            
        # STEP 4 - Create the Token
        token = user.generate_auth_token(600)
            
        # STEP 5 - Send back the token o the client
        return jsonify({'token': token.decode('ascii')})
    else:
        return 'Unrecognized Provider'

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