from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from flask import g
import jwt


# Create flask and connection details
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://restapiuser:KMrx5eSstVERwnFe7YUZCrG775p8VYfi@dpg-chh172ak728sd6n2aak0-a.oregon-postgres.render.com/restapidb'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'KMrx5eSstVERwnFe7YUZCrG775p8VYfi' 
secret_key = app.config['SECRET_KEY']

db = SQLAlchemy(app)

# Database table details
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    contacts = db.relationship('Contact', backref='user', lazy=True)

class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=True)
    phone = db.Column(db.String(20), nullable=False)
    address = db.Column(db.String(255), nullable=True)
    country = db.Column(db.String(100), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Create Database if it doesn't exist
with app.app_context():
    db.create_all()

algorithm = 'HS256'

# Verification for Access
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            token_parts = auth_header.split()

            if len(token_parts) == 2 and token_parts[0].lower() == 'bearer':
                token = token_parts[1]

        if not token:
            return jsonify({'message': 'Authentication token is missing', 'data': {}}), 401

        try:
            # Verify and decode the token using the secret key
            decoded_token = jwt.decode(token, secret_key, algorithms=['HS256'])

            # Store the decoded token in the `g` object for later use
            g.decoded_token = decoded_token

            return f(*args, **kwargs)

        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired', 'data': {}}), 401

        except jwt.InvalidTokenError:
            return jsonify({'message': 'Authentication failed', 'data': {}}), 401

    return decorated


#SignUp
@app.route('/user/signup', methods=['POST'])
def signup():
    data = request.get_json()

    name = data.get('name')
    email = data.get('email')
    password = data.get('password')

    if not name:
        return jsonify({'message': 'Name cannot be left blank', 'data': {}}), 400

    if not email:
        return jsonify({'message': 'Email cannot be left blank', 'data': {}}), 400

    if not password:
        return jsonify({'message': 'Password cannot be left blank', 'data': {}}), 400

    if '@' not in email or '.' not in email:
        return jsonify({'message': 'Email is not valid', 'data': {}}), 400

    hashed_password = generate_password_hash(password, method='sha256')

    user = User(name=name, email=email, password=hashed_password)

    try:
        db.session.add(user)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify({'message': 'Email already registered', 'data': {}}), 400

    payload = {
        'id': user.id,
        'name': user.name,
        'email': user.email
    }

    access_token = jwt.encode(payload, secret_key, algorithm='HS256')

    return jsonify({
        'message': 'User signup complete',
        'data': {
            'access_token': access_token,
            'user': {
                'id': user.id,
                'name': user.name,
                'email': user.email
            }
        }
    }), 200

#Login
@app.route('/user/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email:
        return jsonify({'message': 'Email cannot be left blank', 'data': {}}), 400

    if '@' not in email or '.' not in email:
        return jsonify({'message': 'Email is not valid', 'data': {}}), 400

    if not password:
        return jsonify({'message': 'Password cannot be left blank', 'data': {}}), 400

    user = User.query.filter_by(email=email).first()
    g.current_user = user
    if not user:
        return jsonify({'message': 'Email not registered', 'data': {}}), 400

    if not check_password_hash(user.password, password):
        return jsonify({'message': 'Invalid credentials', 'data': {}}), 401

    payload = {
        'id': user.id,
        'name': user.name,
        'email': user.email
    }

    access_token = jwt.encode(payload, secret_key, algorithm='HS256')

    return jsonify({
        'message': 'Login successful',
        'data': {
            'access_token': access_token,
            'user': {
                'id': user.id,
                'name': user.name,
                'email': user.email
            }
        }
    }), 200


@app.route('/user', methods=['GET'])
@token_required
def get_user():
    user = User.query.get(g.decoded_token['id'])

    if not user:
        return jsonify({'message': 'User not found', 'data': {}}), 404

    return jsonify({
        'message': 'User detail',
        'data': {
            'id': user.id,
            'name': user.name,
            'email': user.email
        }
    }), 200


@app.route('/contact', methods=['POST'])
@token_required
def create_contact():
    data = request.get_json()

    name = data.get('name')
    phone = data.get('phone')
    email = data.get('email')
    address = data.get('address')
    country = data.get('country')

    if not name or not phone:
        return jsonify({'message': 'Name and phone are required', 'data': {}}), 400

    user = User.query.get(g.decoded_token['id'])
    contact = Contact(name=name, phone=phone, email=email, address=address, country=country, user_id=user.id)

    db.session.add(contact)
    db.session.commit()

    return jsonify({
        'message': 'Contact added',
        'data': {
            'id': contact.id,
            'name': contact.name,
            'email': contact.email,
            'phone': contact.phone,
            'address': contact.address,
            'country': contact.country
        }
    }), 200


@app.route('/contact', methods=['GET'])
@token_required
def list_contacts():
    page = int(request.args.get('page', 1))
    limit = int(request.args.get('limit', 10))
    sort_by = request.args.get('sort_by', 'latest')

    user = User.query.get(g.decoded_token['id'])
    contacts_query = Contact.query.filter_by(user_id=user.id) 

    if sort_by == 'latest':
        contacts_query = contacts_query.order_by(Contact.id.desc())
    elif sort_by == 'oldest':
        contacts_query = contacts_query.order_by(Contact.id.asc())
    elif sort_by == 'alphabetically_a_to_z':
        contacts_query = contacts_query.order_by(Contact.name.asc())
    elif sort_by == 'alphabetically_z_to_a':
        contacts_query = contacts_query.order_by(Contact.name.desc())

    contacts = contacts_query.paginate(page=page, per_page=limit)

    contact_list = []
    for contact in contacts.items:
        contact_list.append({
            'id': contact.id,
            'name': contact.name,
            'email': contact.email,
            'phone': contact.phone,
            'address': contact.address,
            'country': contact.country
        })

    return jsonify({
        'message': 'Contact list',
        'data': {
            'list': contact_list,
            'has_next': contacts.has_next,
            'has_prev': contacts.has_prev,
            'page': contacts.page,
            'pages': contacts.pages,
            'per_page': contacts.per_page,
            'total': contacts.total
        }
    }), 200


@app.route('/contact/search', methods=['GET'])
@token_required
def search_contacts():
    page = int(request.args.get('page', 1))
    limit = int(request.args.get('limit', 10))
    sort_by = request.args.get('sort_by', 'latest')
    name = request.args.get('name')
    email = request.args.get('email')
    phone = request.args.get('phone')

    contacts_query = Contact.query.filter_by(user_id=1)  #TODO Replace 1 with the user ID from the access token

    if sort_by == 'latest':
        contacts_query = contacts_query.order_by(Contact.id.desc())
    elif sort_by == 'oldest':
        contacts_query = contacts_query.order_by(Contact.id.asc())
    elif sort_by == 'alphabetically_a_to_z':
        contacts_query = contacts_query.order_by(Contact.name.asc())
    elif sort_by == 'alphabetically_z_to_a':
        contacts_query = contacts_query.order_by(Contact.name.desc())

    if name:
        contacts_query = contacts_query.filter(Contact.name.ilike(f'%{name}%'))

    if email:
        contacts_query = contacts_query.filter(Contact.email.ilike(f'%{email}%'))

    if phone:
        contacts_query = contacts_query.filter(Contact.phone.ilike(f'%{phone}%'))

    contacts = contacts_query.paginate(page=page, per_page=limit)

    contact_list = []
    for contact in contacts.items:
        contact_list.append({
            'id': contact.id,
            'name': contact.name,
            'email': contact.email,
            'phone': contact.phone,
            'address': contact.address,
            'country': contact.country
        })

    return jsonify({
        'message': 'Contact search results',
        'data': {
            'list': contact_list,
            'has_next': contacts.has_next,
            'has_prev': contacts.has_prev,
            'page': contacts.page,
            'pages': contacts.pages,
            'per_page': contacts.per_page,
            'total': contacts.total
        }
    }), 200

