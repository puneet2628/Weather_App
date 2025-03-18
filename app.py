from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy 
from flask_wtf import FlaskForm
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from flask_mail import Mail, Message
import bcrypt
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email
import os
import random
import string
from dotenv import load_dotenv  # Import dotenv
from sqlalchemy import func
from itsdangerous import URLSafeTimedSerializer as Serializer, SignatureExpired

# Load environment variables from .env file
load_dotenv()

# Initialize Flask app and extensions
app = Flask(__name__)

# Load configuration from environment variables
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY') or 'your_default_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI') or 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Disable SQLAlchemy modification tracking
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = bool(os.getenv('MAIL_USE_TLS', True))
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')  # Your email for sending password resets
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')  # Your email password or app-specific password

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
mail = Mail(app)

# User model with Flask-Login integration
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=func.now())
    is_confirmed = db.Column(db.Boolean, default=False)
    
    def is_active(self):
        return True

    def get_id(self):
        return str(self.id)

    def is_authenticated(self):
        return True  # User is assumed authenticated once logged in

    def is_anonymous(self):
        return False  # User is not anonymous

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Error Handlers
@app.errorhandler(404)
def page_not_found(error):
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_server_error(error):
    return render_template('errors/500.html'), 500

@app.errorhandler(403)
def forbidden(error):
    return render_template('errors/403.html'), 403

@app.errorhandler(400)
def bad_request(error):
    return render_template('errors/400.html'), 400

# Forms
class SigninForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign In')

class SignupForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign Up')

class ResetPasswordForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Reset Password')

class ChangePasswordForm(FlaskForm):
    old_password = PasswordField('Old Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm New Password', validators=[DataRequired()])
    submit = SubmitField('Change Password')

# Routes
@app.route('/')
def index():
    return render_template('index.html')

# Signup route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    try:
        if form.validate_on_submit():
            # Check if the email already exists
            existing_user = User.query.filter_by(email=form.email.data).first()
            if existing_user:
                flash('Email already exists. Please use a different email address.', 'danger')
                return redirect(url_for('signup'))

            # Hash the password using bcrypt
            hashed_password = bcrypt.hashpw(form.password.data.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()

            # Send confirmation email
            send_confirmation_email(new_user)

            flash('Account created successfully! Please check your email to confirm your account.', 'success')
            return redirect(url_for('signin'))
    except Exception as e:
        db.session.rollback()  # Rollback the transaction if an error occurs
        flash(f'Error during signup: {str(e)}', 'danger')
    return render_template('signup.html', form=form)

# Generate confirmation token
def generate_confirmation_token(email):
    serializer = Serializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt='email-confirmation')

# Send confirmation email
def send_confirmation_email(user):
    token = generate_confirmation_token(user.email)
    confirm_url = url_for('confirm_email', token=token, _external=True)
    msg = Message('Email Confirmation', recipients=[user.email], sender=app.config['MAIL_USERNAME'])
    msg.body = f'Your email confirmation link is: {confirm_url}'
    mail.send(msg)


# Confirm email route
@app.route('/confirm/<token>')
def confirm_email(token):
    try:
        serializer = Serializer(app.config['SECRET_KEY'])
        email = serializer.loads(token, salt='email-confirmation', max_age=3600)  # Token expires in 1 hour
        user = User.query.filter_by(email=email).first()
        if user:
            user.is_confirmed = True
            db.session.commit()
            flash('Your email has been confirmed!', 'success')
            return redirect(url_for('signin'))
    except SignatureExpired:
        flash('The confirmation link has expired.', 'danger')
    except Exception as e:
        flash(f'Error during email confirmation: {str(e)}', 'danger')
    return redirect(url_for('signin'))

# Signin route
@app.route('/signin', methods=['GET', 'POST'])
def signin():
    form = SigninForm()
    try:
        if form.validate_on_submit():
            user = User.query.filter_by(username=form.username.data).first()
            if user and bcrypt.checkpw(form.password.data.encode('utf-8'), user.password.encode('utf-8')):
                if user.is_confirmed:  # Check if the email is confirmed
                    login_user(user)
                    flash('Sign in successful!', 'success')
                    return redirect(url_for('profile'))
                else:
                    flash('Please confirm your email address first.', 'warning')
            else:
                flash('Sign in failed. Check your username and/or password.', 'danger')
    except Exception as e:
        flash(f'Error during Sign in: {str(e)}', 'danger')
    return render_template('signin.html', form=form)

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', username=current_user.username)

@app.route('/logout')
@login_required
def logout():
    try:
        logout_user()
        flash('You have been logged out.', 'info')
    except Exception as e:
        flash(f'Error during logout: {str(e)}', 'danger')
    return redirect(url_for('signin'))

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    form = ResetPasswordForm()
    try:
        if form.validate_on_submit():
            user = User.query.filter_by(email=form.email.data).first()
            if user:
                token = ''.join(random.choices(string.ascii_letters + string.digits, k=6))  # simple token
                msg = Message('Password Reset Request', recipients=[form.email.data])
                msg.body = f'Your password reset token is {token}.'
                mail.send(msg)
                flash('Password reset link sent to your email.', 'info')
                return redirect(url_for('signin'))
            flash('Email not found.', 'danger')
    except Exception as e:
        flash(f'Error during password reset: {str(e)}', 'danger')
    return render_template('reset_password.html', form=form)

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    try:
        if form.validate_on_submit():
            user = current_user
            if bcrypt.checkpw(form.old_password.data.encode('utf-8'), user.password.encode('utf-8')):
                if form.new_password.data == form.confirm_password.data:
                    hashed_password = bcrypt.hashpw(form.new_password.data.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                    user.password = hashed_password
                    db.session.commit()
                    flash('Password changed successfully!', 'success')
                    return redirect(url_for('profile'))
                else:
                    flash('New passwords do not match.', 'danger')
            else:
                flash('Incorrect old password.', 'danger')
    except Exception as e:
        flash(f'Error during password change: {str(e)}', 'danger')
    return render_template('change_password.html', form=form)

@app.route('/delete_account', methods=['GET', 'POST'])
@login_required
def delete_account():
    if request.method == 'POST':
        try:
            user = current_user
            db.session.delete(user)
            db.session.commit()
            flash('Your account has been deleted successfully.', 'success')
            logout_user()
            return redirect(url_for('login'))
        except Exception as e:
            flash(f'Error during account deletion: {str(e)}', 'danger')
            return redirect(url_for('profile'))
    return render_template('delete_account.html')

# Ensure the app creates all tables when starting
if __name__ == "__main__":
    try:
        with app.app_context():
            db.create_all()
        app.run(debug=True)
    except Exception as e:
        print(f"Error: {str(e)}")
