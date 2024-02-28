from flask import Flask, render_template, request, redirect, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'ILIke_huge_BANANAS53!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), default='user', nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def is_authenticated(self):
        return True  # Assuming all users are authenticated

    def is_active(self):
        return True  # Assuming all users are active

    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)

# Create a login manager similar to flask_login
class LoginManager:
    def __init__(self, app):
        self.app = app

    def init_app(self, app):
        pass  # Initialization logic if needed

    def user_loader(self, func):
        self.load_user = func

    def login_view(self, view):
        pass  # Logic if needed

login_manager = LoginManager(app)
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            # Simulate login_user function
            user.authenticated = True
            flash('Login successful!', 'success')

            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('personal_panel'))
        else:
            flash('Login unsuccessful. Please check your username and password.', 'danger')

    return render_template('login.html')

@app.route('/logout')
def logout():
    # Simulate logout_user function
    current_user.authenticated = False
    return redirect(url_for('home'))

# Admin dashboard and other routes remain the same

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Your user creation or update logic here
        db.session.commit()

    app.run(debug=True, port=80)
