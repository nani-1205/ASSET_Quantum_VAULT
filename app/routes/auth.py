from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from ..forms import LoginForm, SignupForm
from ..models import User
from ..extensions import mongo
from datetime import datetime, timezone

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.index')) # Or dashboard

    form = LoginForm()
    if form.validate_on_submit():
        user = User.get_by_username(form.username.data)
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember_me.data)
            user.check_and_revoke_temp_admin() # Check temp status on login
            flash('Login successful!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('main.index'))
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('login.html', title='Login', form=form)

@auth_bp.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))

    form = SignupForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        # Check if it's the very first user being created
        is_first_user = mongo.db.users.count_documents({}) == 0
        is_admin = is_first_user # Make the first user admin

        try:
            user_data = {
                'username': form.username.data,
                'password_hash': hashed_password,
                'is_admin': is_admin,
                'is_temp_admin': False,
                'temp_admin_expiry': None
                # Add 'email': form.email.data if using email
            }
            mongo.db.users.insert_one(user_data)
            flash('Account created successfully! Please log in.', 'success')
            if is_admin:
                 flash('You have been registered as the first Admin user.', 'info')
            return redirect(url_for('auth.login'))
        except Exception as e:
            flash(f'An error occurred during signup: {e}', 'danger')

    return render_template('signup.html', title='Sign Up', form=form)

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('auth.login'))