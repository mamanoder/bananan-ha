import login
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)
app.config['SECRET_KEY'] = 'ILIke_huge_BANANAS53!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

def load_user(user_id):
    return User.query.get(int(user_id))


class User(UserMixin, db.Model):
    __tablename__ = 'admin'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    role = db.Column(db.String(20), default='user', nullable=False)

# new_user = User(username='example_user', password='password', role='admin')
# db.session.add(new_user)
# db.session.commit()

@app.route('/')
def home():
    return render_template('home.html')


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()

        if user and password == user.password:
            login_user(user)
            flash('Login successful!', 'success')

            # Check if the user is an admin before accessing role attribute
            if current_user.is_authenticated and current_user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('personal_panel'))
        else:
            flash('Login unsuccessful. Please check your username and password.', 'danger')

    return render_template('login.html')
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if password != confirm_password:
            flash('Passwords do not match. Please try again.', 'danger')
        else:
            existing_user = User.query.filter_by(username=username).first()
            if existing_user:
                flash('Username already exists. Please choose a different username.', 'danger')
            else:
                new_user = User(username=username, password=password)
                db.session.add(new_user)
                db.session.commit()
                flash('Registration successful! You can now log in.', 'success')
                return redirect(url_for('login'))

    return render_template('register.html')


@login_manager.user_loader
def load_user(user_id):
    return db.session.query(User).get(int(user_id))

@app.before_request
def before_request():
    current_user.get_id()


@app.route('/admin')
@login_required
def admin_dashboard():
    if current_user.is_authenticated and current_user.role == 'admin':
        return render_template('admin.html')
    else:
        flash('Access denied. You must be an admin to view this page.', 'danger')
        return redirect(url_for('home'))

@app.route('/panel')
@login_required
def personal_panel():
    return render_template('panel.html')




@app.route('/admin/edit_users')
@login_required
def admin_edit_users():
    if current_user.role == 'admin':
        # Add logic to display or edit users here if needed
        return render_template('admin_panel.html')
    else:
        flash('Access denied. You must be an admin to view this page.', 'danger')
        return redirect(url_for('home'))

# ... (your existing routes)




@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Your user creation or update logic here
        db.session.commit()

    app.run(debug=True, port=80)
