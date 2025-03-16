from flask import Flask, jsonify, request, session, render_template, url_for, redirect
import configparser
import json
import secrets
import firebase_admin 
from firebase_admin import auth, credentials
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from sqlalchemy import text
from sqlalchemy.ext.automap import automap_base
from sqlalchemy.exc import IntegrityError
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity
import base64


app = Flask(__name__)

#Firebase setup
cred = credentials.Certificate("sdp-project-30503-firebase-adminsdk-fzx84-99c1f12b5f.json")
firebase_admin.initialize_app(cred)

#Reading config
config = configparser.ConfigParser()
config.read('util/config.ini')

#Secret key for sessions
secret_key = secrets.token_hex(16)
app.secret_key = secret_key

#JWT manager
app.config['JWT_SECRET_KEY'] = secrets.token_urlsafe(16)
jwt = JWTManager(app)


app.config['SQLALCHEMY_DATABASE_URI'] = f'postgresql://{config['Database']['Username']}:{config['Database']['Password']}@{config['Database']['Host']}/{config['Database']['Database']}'
db = SQLAlchemy(app)
migrate = Migrate(app, db)

@app.before_request #DEBUG ONLY
def make_session_permanent():
    session.permanent = True


class Users(db.Model):
    uid = db.Column(db.String(28), primary_key=True) #Maximum length for uid 28 because of firebase uid length
    username = db.Column(db.String(80), unique=True, nullable=False)
    profile_pic = db.Column(db.LargeBinary, nullable=True)  # Column to store the image data


    def __repr__(self):
        return f'<User {self.username}>'
    
    @classmethod
    def username_exists(cls, username):
        """
        Check if a username already exists in the database.

        Args:
            username (str): The username to check.

        Returns:
            bool: True if the username exists, False otherwise.
        """
        return bool(cls.query.filter_by(username=username).first())

class Friends(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id_1 = db.Column(db.String(28), db.ForeignKey('users.uid'), nullable=False)
    user_id_2 = db.Column(db.String(28), db.ForeignKey('users.uid'), nullable=False)
    accepted = db.Column(db.Boolean, default=False, nullable=False)

    user1 = db.relationship('Users', foreign_keys=[user_id_1])
    user2 = db.relationship('Users', foreign_keys=[user_id_2])

    def __repr__(self):
        return f'<Friends {self.user1.username} - {self.user2.username}>'


with app.app_context():
    Base = automap_base()
    Base.prepare(db.engine, reflect=True)

#Site endpoints
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login')
def login():
    return render_template('login.html')


@app.route('/signin')
def signin():
    return render_template('signin.html')


@app.route('/signup')
def signup():
    return render_template('signup.html')


@app.route('/visualiser')
def visualiser():
    if not session.get("uid"):
        return redirect(url_for('signin'))
    else:     
        return render_template('visualiser.html', current_user = session.get('uid'))


@app.route('/friends')
def friends():
    if not session.get("uid"):
        return redirect(url_for('signin'))
    else:     
        return render_template('friends.html')
    

@app.route('/profile')
def profile():
    if not session.get("uid"):
        return redirect(url_for('signin'))
    else:     
        return render_template('profile.html')


#API endpoints
@app.route('/datasets', methods=['GET'])
def get_dataset_list():
    # Read the dataset names from the file
    with open('util/dataset_list.json', 'r') as file:
        datasets = json.load(file)
    
    dataset_info = [{'name': dataset['name'], 'primary_attribute': dataset['primary_attribute']} for dataset in datasets]
    
    # Return the dataset list as JSON
    return jsonify({'datasets': dataset_info})


@app.route('/dataset_structure', methods=['GET'])
def get_table_structure():
    # Get dataset name from query parameters
    dataset_name_param = request.args.get('dataset_name')

    # Check if dataset_name parameter is provided
    if not dataset_name_param:
        return jsonify({'error': 'Dataset name parameter is required'}), 400

    # Extract dataset name and replace '-' with '_'
    dataset_name = dataset_name_param.split('/', 1)[-1].replace('-', '_')

    # Check if the table exists in the database
    if table_exists(dataset_name):
        pass
    else:
        return jsonify({'error': f'Table "{dataset_name}" does not exist'}), 404

    result = db.session.execute(
        text('SELECT column_name, data_type FROM information_schema.columns WHERE table_name = :dataset_name ORDER BY ordinal_position'), 
        {'dataset_name': dataset_name})
    data = [list(row) for row in result]
    return jsonify({'structure': data}), 200


@app.route('/dataset_data', methods=['GET'])
def get_table_data():
    dataset_name_param = request.args.get('dataset_name')

    # Check if dataset_name parameter is provided
    if not dataset_name_param:
        return jsonify({'error': 'Dataset name parameter is required'}), 400
    
    # Extract dataset name and replace '-' with '_'
    dataset_name = dataset_name_param.split('/', 1)[-1].replace('-', '_')


    if table_exists(dataset_name):
        pass
    else:
        return jsonify({'error': f'Table "{dataset_name}" does not exist'}), 404
    
    query = text(f'SELECT * from {dataset_name}') #Can't use parameterised query for table
    result = db.session.execute(query)
    data = [list(row) for row in result]
    return jsonify({'data': data}), 200


@app.route('/dataset_parameters', methods=['GET'])
def get_table_parameters():
    dataset_name_param = request.args.get('dataset_name')

    if not dataset_name_param:
        return jsonify({'error': 'Dataset name parameter is required'}), 400
    
    # Extract dataset name and replace '-' with '_'
    dataset_name = dataset_name_param.split('/', 1)[-1].replace('-', '_')

    if table_exists(dataset_name):
        pass
    else:
        return jsonify({'error': f'Table "{dataset_name}" does not exist'}), 404
    
    with open('util/dataset_list.json', 'r') as file:
        datasets = json.load(file)
    
    for dataset in datasets:
        if dataset['name'] == dataset_name_param:
            for attribute in dataset['other_attributes']:
                if not attribute['is_number']:
                    column_name = attribute['attribute_name']
                    query = text(f'select distinct "{column_name}" from {dataset_name}') 
                    result = db.session.execute(query)
                    data = [list(row) for row in result]
                    attribute['selectable_values'] = data 
            return jsonify(dataset.get('other_attributes', []))
    
    # If no dataset matches, return an error message
    return jsonify({"error": "Dataset not found"}), 404


@app.route('/dataset_user_update', methods=['POST'])
def receive_data():
    incoming_data = request.json
    dataset_param = incoming_data.get('selectedDataset')
    data = incoming_data.get('data')

    dataset_name = dataset_param.split('/', 1)[-1].replace('-', '_')
    dataset_name += '_user'
    data = {key: value for key, value in data.items() if value not in [None, '']}

    # Process the received data as needed
    try:
        columns = ', '.join(data.keys())
        values_placeholder = ', '.join([f":{key}" for key in data.keys()])
        update_clause = ', '.join([f'{key}=excluded.{key}' for key in data.keys()])
        sql = text(f"INSERT INTO {dataset_name} (userid, {columns}) VALUES (:userid, {values_placeholder}) ON CONFLICT(userid) DO UPDATE SET {update_clause}")

        # Prepare the data as a dictionary with named placeholders for the execute method
        values = {"userid": session['uid']}
        for key, value in data.items():
            if value is not None:
                print(f'Key: {key}, Value: {value}')
                values[key] = value

        # Execute the SQL query with data parameters
        db.session.execute(sql, values)
        db.session.commit()

        return jsonify('Data inserted successfully')
    
    except IntegrityError as e:
        db.session.rollback()
        print(e)
        return jsonify(f'Error: {str(e)}'), 400
    except Exception as e:
        print(e)
        return jsonify(f'Error: {str(e)}'), 500

@app.route('/dataset_data_user', methods=['GET']) #WIP
def dataset_data_user():
    dataset_name_param = request.args.get('dataset_name')
    uid_param = request.args.get('uid')

    if not dataset_name_param:
        return jsonify({'error': 'Dataset name parameter is required'}), 400

    if not uid_param:
        return jsonify({'error': 'UID parameter is required'}), 400
    
    dataset_name = dataset_name_param.split('/', 1)[-1].replace('-', '_')
    dataset_name = dataset_name + '_user'

    if table_exists(dataset_name):
        pass
    else:
        return jsonify({'error': f'Table "{dataset_name}" does not exist'}), 404
    
    data = []
 
    result = db.session.execute(
    text(f'SELECT *, (SELECT username FROM users WHERE uid = :userid) AS username FROM {dataset_name} WHERE userid = :userid'), 
    {'userid': uid_param})
    data.extend([list(row) for row in result])
       
    return jsonify(data)


@app.route('/dataset_data_friends', methods=['GET'])
def dataset_data_friends():
    dataset_name_param = request.args.get('dataset_name')
    uid = request.args.get('uid')
    if not dataset_name_param:
        return jsonify({'error': 'Dataset name is required'}), 400
    
    if not uid:
        return jsonify({'error': 'UID is required'}), 400
    
    dataset_name = dataset_name_param.split('/', 1)[-1].replace('-', '_')
    dataset_name = dataset_name + '_user'

    if table_exists(dataset_name):
        pass
    else:
        return jsonify({'error': f'Table "{dataset_name}" does not exist'}), 404

    friends = Friends.query.filter(
        db.or_(Friends.user_id_1 == uid, Friends.user_id_2 == uid),
        Friends.accepted == True
    ).all()
    
    data = []
    for friend in friends:
        if friend.user_id_1 != uid:    
            result = db.session.execute(
                text(f'SELECT *, (SELECT username FROM users WHERE uid = :userid) AS username FROM {dataset_name} WHERE userid = :userid'), 
                {'userid': friend.user_id_1})
            data.extend([list(row) for row in result])
        elif friend.user_id_2 != uid:
                result = db.session.execute(
                text(f'SELECT *, (SELECT username FROM users WHERE uid = :userid) AS username FROM {dataset_name} WHERE userid = :userid'), 
                {'userid': friend.user_id_2})
                data.extend([list(row) for row in result])
    return jsonify(data)


@app.route('/friend_list/<uid>', methods=['GET'])
def get_friend_list(uid):
    if not uid:
        return jsonify({'error': 'UID parameter is required'}), 400
    
    friends = Friends.query.filter(
        ((Friends.user_id_1 == uid) | (Friends.user_id_2 == uid)) &
        (Friends.accepted == True)
    ).all()

    friend_list = []
    for friend in friends:
        if friend.user1.uid == uid:
            friend_data = {"username": friend.user2.username}
        else:
            friend_data = {"username": friend.user1.username}
        friend_list.append(friend_data)
    
    return jsonify(friend_list)


@app.route('/friend_list_pending/<uid>', methods=['GET'])
def get_friend_list_pending(uid):
    if not uid:
        return jsonify({'error': 'UID parameter is required'}), 400
    
    # Query for pending friend requests where user2 is the recipient and the request is not accepted
    friends = Friends.query.filter(
        (Friends.user_id_2 == uid) & 
        (Friends.accepted == False)
    ).all()

    friend_list = []
    for friend in friends:
        if friend.user_id_1 != uid:  # Ensure user1 is not the requester
            friend_data = {
                "friend": {
                    "username": friend.user1.username
                }
            }
            friend_list.append(friend_data)
    
    return jsonify(friend_list)




@app.route('/friend_request', methods=['POST']) #WIP
def send_friend_request():
    uid1 = request.json['uid1']
    username2 = request.json['username2']
    
    if not uid1:
        return jsonify({'error': 'Sender is required'}), 400
    
    if not username2:
        return jsonify({'error': 'Receiver is required'}), 400
    
    if not Users.username_exists(username2):
        return redirect(url_for('friends'))


    uid_from_username = Users.query.filter_by(username=username2).first()
    uid2 = uid_from_username.uid

    new_friendship = Friends(user_id_1=uid1, user_id_2=uid2, accepted=False)
    db.session.add(new_friendship)
    db.session.commit()
    
    return jsonify({'message': 'Friend request successful'}), 200


@app.route('/friend_request_accept', methods=['POST']) #WIP (need to add authentication)
def accept_friend_request():
    username1 = request.json['username1']
    uid2 = request.json['uid2']
    
    if not username1:
        return jsonify({'error': 'Sender is required'}), 400
    
    if not uid2:
        return jsonify({'error': 'Receiver is required'}), 400
    uid_from_username = Users.query.filter_by(username=username1).first()
    uid1 = uid_from_username.uid

    friendship = Friends.query.filter(
        ((Friends.user_id_1 == uid1) & (Friends.user_id_2 == uid2)) |
        ((Friends.user_id_1 == uid2) & (Friends.user_id_2 == uid1))
    ).first()

    if friendship:
        friendship.accepted = True
    db.session.commit()

    return jsonify({'message': 'Friend request accepted'}), 200


@app.route('/friend_request_deny', methods=['POST']) #WIP (need to add authentication)
def deny_friend_request():
    username1 = request.json['username1']
    uid2 = request.json['uid2']
    
    if not username1:
        return jsonify({'error': 'Sender is required'}), 400
    
    if not uid2:
        return jsonify({'error': 'Receiver is required'}), 400
    uid_from_username = Users.query.filter_by(username=username1).first()
    uid1 = uid_from_username.uid

    try:
        friendship = Friends.query.filter(
            ((Friends.user_id_1 == uid1) & (Friends.user_id_2 == uid2)) 
        ).first()
        print(friendship)
        if friendship:
            db.session.delete(friendship)
        db.session.commit()

        return jsonify({'message': 'Friend request denied'}), 200
    except Exception as e:
        db.session.rollback()
    return jsonify({'error': 'Server error', 'details': str(e)}), 500

@app.route('/friend_remove', methods=['POST']) #WIP (need to add authentication and the ability to remove friends)
def remove_friend():
    username1 = request.json['username1']
    uid2 = request.json['uid2']
    return jsonify({'message': 'Friend removed successful'}), 200


@app.route('/check_username', methods=['POST'])
def check_username():
    username = request.json['username']
    user_exists = Users.query.filter_by(username=username).first() is not None
    return jsonify({'user_exists': user_exists})

@app.route('/user_create', methods=['POST'])
def user_create():
    username = request.json['username']
    uid = request.json['uid']

    if not username:
        return jsonify({'error': 'Username is required'}), 400
    
    if not uid:
        return jsonify({'error': 'UID is required'}), 400
    
    with open('static/images/profile.png', 'rb') as f:
        image_data = f.read()

    new_user = Users(uid=uid, username=username, profile_pic=image_data)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({f'message': '{username} got created'})


@app.route('/logout', methods=['GET']) #WIP
def logout():
    session.pop('uid', None)  # Clear UID from session
    session.pop('username', None)
    return redirect(url_for('index'))


@app.route('/verify_token', methods=['POST'])
def verify_token():
    id_token = request.json.get('idToken')
    try:
        # Verify the ID token while checking if it is revoked
        decoded_token = auth.verify_id_token(id_token)
        uid = decoded_token['uid']
        # Here you can add the user ID to the session or create a user in your DB 
        session['uid'] = uid
        user = Users.query.get(uid)
        if user:
            session['username'] = user.username
        else:
            session['username'] = None
        return jsonify({'status': 'success', 'uid': uid}), 200
    except auth.AuthError:
        return jsonify({'status': 'error', 'message': 'Invalid token'}), 401


@app.route('/protected', methods=['GET']) #Maybe not important
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200


@app.route('/get_username')
def get_username():
    username = session.get('username')
    if username:
        return jsonify(is_logged_in=True, username=username)
    return jsonify(is_logged_in=False, username=None)


#WIP
@app.route('/user_delete', methods=['POST'])
def user_delete():
    uid = request.json['uid']

    if not uid:
        return jsonify({'error': 'UID is required'}), 400

    if not session.get("uid"):
        return jsonify({'error': 'Unauthorized'}), 401
        
    user = Users.query.filter_by(uid=uid).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    #Deletes all friend entries
    Friends.query.filter((Friends.user_id_1 == uid) | (Friends.user_id_2 == uid)).delete(synchronize_session=False)

    #Deletes the user
    db.session.delete(user)
    db.session.commit()
    return jsonify({f'message': '{username} got deleted'}), 200


@app.route('/user_upload_picture', methods=['POST'])
def user_upload_picture():
    file = request.files['profilePic']

    if not session.get("uid"):
        return jsonify({'error': 'Unauthorized'}), 401
    
    if not file:
        return jsonify({'error': 'Missing data'}), 400

    if file.content_type not in ['image/jpeg', 'image/png']:
        return jsonify({'error': 'Only JPEG and PNG files are allowed'}), 400
    
    file_data = file.read()  # Read the file data

    user = Users.query.filter_by(uid=session.get('uid')).first()

    user.profile_pic = file_data  # Update existing user
     
    db.session.commit()
    return jsonify({'message': 'File uploaded successfully'}), 200


@app.route('/user_get_picture', methods=['GET'])
def user_get_picture():
    uid = request.args['uid']

    if not uid:
        return jsonify({'error': 'Unauthorized'}), 401
    
    user = Users.query.filter_by(uid=uid).first()

    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    profile_pic = user.profile_pic
    db.session.commit()
    return jsonify({'profile_pic': base64.b64encode(profile_pic).decode('utf-8')}), 200

@app.route('/test', methods=['GET'])
def test():
    dataset_name_param = request.args.get('dataset_name')
    uid = request.args.get('uid')
    if not dataset_name_param:
        return jsonify({'error': 'Dataset name is required'}), 400
    
    if not uid:
        return jsonify({'error': 'UID is required'}), 400
    
    dataset_name = dataset_name_param.split('/', 1)[-1].replace('-', '_')
    dataset_name = dataset_name + '_user'

    if table_exists(dataset_name):
        pass
    else:
        return jsonify({'error': f'Table "{dataset_name}" does not exist'}), 404

    friends = Friends.query.filter(
        db.or_(Friends.user_id_1 == uid, Friends.user_id_2 == uid),
        Friends.accepted == True
    ).all()
    
    data = []
    for friend in friends:
        if friend.user_id_1 != uid:    
            result = db.session.execute(
                text(f'SELECT *, (SELECT username FROM users WHERE uid = :userid) AS username FROM {dataset_name} WHERE userid = :userid'), 
                {'userid': friend.user_id_1})
            data.extend([list(row) for row in result])
        elif friend.user_id_2 != uid:
                result = db.session.execute(
                text(f'SELECT *, (SELECT username FROM users WHERE uid = :userid) AS username FROM {dataset_name} WHERE userid = :userid'), 
                {'userid': friend.user_id_2})
                data.extend([list(row) for row in result])
    return jsonify(data)

#Methods
def table_exists(table_name):
    result = db.session.execute(
        text('SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = :table_name)'), 
        {'table_name': table_name})
    if result is not None:
        return True
    return False

#Starting Flask server
if __name__ == "__main__":
    app.run(port=8000, debug=True)
    with app.app_context():
        db.create_all()
