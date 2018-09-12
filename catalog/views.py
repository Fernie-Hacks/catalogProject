from models import Base, User, Category, Item
from flask import Flask, jsonify, request, url_for, g, render_template, abort, flash, redirect
from flask_bootstrap import Bootstrap
#from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine, and_

from flask_httpauth import HTTPBasicAuth

# Renamed the import to login_session
# This import functions as a dictionary  which can store values for the longevity
# of a user's session. 
from flask import session as login_session
import json
import string, random
import requests
from flask import make_response

# Import needed to create flow objects, and exceptions to handle the response from providers  
from oauth2client.client import flow_from_clientsecrets # Contains OAuth parameter
from oauth2client.client import FlowExchangeError # To Catch errors during exchanges
import httplib2
from flask.helpers import make_response

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
        user = session.query(User).filter_by(id = user_id).one()
    else: 
        user = session.query(User).filter_by(username = username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True

def getUserID(email):
    try:
        user = session.query(User).filter_by(email = email).one()
        return user.id
    except:
        return None
    
def createUser(login_session):
    newUser = User(username = login_session['username'], email = 
                   login_session['email'], picture = login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email = login_session['email']).one()
    return user.id

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
    # Create 'state' token to protect against anti-forgery attacks 
    state = "".join(random.choice(string.ascii_uppercase + string.digits)
                    for x in range(32))
    # Populate state with the unique token, to late verify against a requests
    login_session['state'] = state
    return render_template('login.html', STATE=state)

@app.route('/gconnect/oauth', methods = ['POST'])
def gconnect():
    # STEP 1 - Validate state token
    if request.args.get('state') != login_session['state']:
        # Making sure requests are being made by the user
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    
    # STEP 2 - Parse the auth code
    auth_code = request.data
    # STEP 3 Exchange for a token
    try:
        # Upgrade the authorization code into a credentials oauth object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        # Specifies with 'postmessage' that this is the one time code my server will be sending (as per sign in div)
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(auth_code)
    except FlowExchangeError:
        response = make_response(json.dumps('Failed to upgrade the authorization code'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    
    # STEP 4 - Check that the access token is valid
    access_token = credentials.access_token 
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    
    # STEP 5 - If there was an error in the access token return a 500 error
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response
    
    # STEP 6 - Verify the access token is used for the intended user
    gplus_id = credentials.id_token['sub'] # Sub is obtained from the Google resource openid 
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user Id doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    
    # Step 7 - Verify that the access token is valid for this APP.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match App's."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    
    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    
    # Step 8 - Check if user is already logged in (Can remove later)
    if stored_access_token is None and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps("Current user is already connected."), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    
    # Store the access token in the session for late use
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = stored_gplus_id
    
    # Get user's info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)
    
    data = answer.json()
    
    login_session['provider'] = 'google'
    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
        
    login_session['user_id'] = user_id
        
    output = ''    
    output += '<h1> Welcome, '
    output += login_session['username']
    output += '!</h1>'
    
    flash("You are now logged in as %s" % login_session['username'])
    
    
    # STEP 9 - Send back the token o the client
    return output    

def gdisconnect():
    # Only disconnect if user is already logged in.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response

def fbdisconnect():
    pass

@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['access_token']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('index'))
    else:
        flash("You were not logged in")
        return redirect(url_for('index'))    

@app.route("/<string:category_name>/items")
def showCategoryItems(category_name):
    category = session.query(Category).filter_by(name = category_name).one()
    categories = session.query(Category).order_by(Category.id).all()
    items = session.query(Item).filter_by(cat_id = category.id).all()
    return render_template('showCategoryItems.html', categories = categories, items 
                           = items, category_name = category_name )

@app.route("/<string:category_name>/<string:item_name>")
def showItem(category_name, item_name):
    category = session.query(Category).filter_by(name = category_name).one()
    item = session.query(Item).filter_by(name = item_name).one()
    if 'username' not in login_session:
        return render_template('showItem.html', item = item)
    else:
        return render_template('showItemLoggedOn.html', item = item)

@app.route("/newItem", methods=['GET','POST'])
def newItem():
    if 'username' not in login_session:
        return redirect('/')
    if request.method == 'POST':
        cat_id = session.query(Category.id).\
            filter(Category.name == request.form['category']).\
            scalar()
        user_id = login_session['user_id']
        newItem = Item(name = request.form['name'], description = 
                           request.form['description'], cat_id = 
                           cat_id, cat_name = 
                           request.form['category'],  user_id = user_id)
        session.add(newItem)
        session.commit()
        flash('New Menu %s Item Successfully Created' % (newItem.name))
        return redirect(url_for('index'))
    else:
        categories = session.query(Category).order_by(Category.id).all()
        return render_template('newItem.html', categories = categories)

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
    app.secret_key = 'secret_key_for_github'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)