from sqlalchemy import Column, Integer, String, ForeignKey, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
import random, string
# Password Hashing dedicated library 
# Support for sha256_crypt and sha512_crypt
from passlib.apps import custom_app_context as pwd_context
# Cryptographically signed message keeps user info, for token based authentication 
from itsdangerous import(
    TimedJSONWebSignatureSerializer as Serializer, 
    BadSignature, 
    SignatureExpired
)
from sqlalchemy.sql.expression import exists

Base = declarative_base()
# Secret key used to serialize and decrypt password
secret_key = ''.join(random.choice(string.ascii_uppercase + string.digits) 
                     for x in xrange(32))

class User(Base):
    __tablename__ = 'user'
    
    id = Column(Integer, primary_key=True)
    username = Column(String(32), index=True)
    picture = Column(String)
    email = Column(String, index=True)
    
    # Keep Password Hash in DB only avoid security issues if DB is compromised
    # The hash is an algorithm that can map digital data 
    # of arbitrary size to digital data of fixed sized
    password_hash = Column(String(64)) 
    
    # Converts a String to a hash
    # Function will take user's password 
    # & convert to an arbitrary size and random character String
    def hash_password(self, password):
        self.password_hash = pwd_context.hash(password)
    
    # Function takes in a String and validates password
    # It uses passlib.app 'verify' function 
    # to cross check the password with the hash.
    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)
    
    # Function that hides the id of the user in a dictionary 
    # Fixed expiration time
    # Uses itsdangerous function dumps to create a signed string 
    # It i staking a dictionary item (Using users's DB id with value)
    def generate_auth_token(self, expiration=600):
        s = Serializer(secret_key, expires_in = expiration)
        return s.dumps({'id': self.id})
    
    # Static Function to determine user
    # Takes token uses the load function of itsdangerous to retrieve user
    # *** Reverse of dumps this retrieves the id dictionary object 
    # Needs to be static since we do not know user until token is decoded
    @staticmethod
    def verify_auth_token(token):
        s = Serializer(secret_key)
        try:
            data = s.loads(token)
        except SignatureExpired:
            # Token was valid but it is expired
            return None
        except BadSignature:
            # Invalid Token
            return None
        user_id = data['id']
        return user_id
    
class Category(Base):
    __tablename__ = 'category'
   
    id = Column(Integer, primary_key=True)
    name = Column(String(50), nullable=False, index=True, unique=True)  
    
    @property
    def serialize(self):
        # Return Category details in a easy serialized way 
        # To be used for JSON response.
        return {
            'name'      : self.name,
            'id'        : self.id   
        }

class Item(Base):
    __tablename__ = 'item'
    
    id = Column(Integer, primary_key=True)
    name = Column(String(50), nullable=False)
    description = Column(String(250))
    cat_id = Column(Integer, ForeignKey('category.id'))
    cat_name = Column(String(50))
    category = relationship(Category, backref='items')
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)
    
    @property
    def serialize(self):
        # Return item's details in a easy serialized way
        # To be used for JSON response.
        return {
            'cat_id'        : self.cat_id,
            'description'   : self.description,
            'id'            : self.id,
            'item'          : self.name
        }
    
# Creates an engine which will use a Dialect & a Pool to interpret a specific
# DB's API in our case we are creating an object tailored to SQLite        
engine = create_engine('sqlite:///catalog.db')

# Metadata is a container object that has features that describe database(s).
# Create_all is a function to create a new DB 
# given the metadata that describes such DB(s).
# *** It issues CREATE statements only if tables do not already exist
Base.metadata.create_all(engine)

# Add the Categories to the DB 
# Project specifications did not provide details on user's ability to 
# create/edit/delete categories
DBSession = sessionmaker(bind=engine)
session = DBSession()

categoryNames = ["Soccer", "Basketball", "Baseball", "Frisbee", 
                 "Snowboarding", "Rock Climbing", 
                 "Foosball", "Skating", "Hockey" ]

for c in categoryNames:
    category = Category(name=c)
    # Check if category name is already present 
    isExistent = session.query(exists().where(Category.name == c)).scalar()
    if not isExistent:
        session.add(category)
        session.commit()  

