from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, TextAreaField, SelectField, DateTimeLocalField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError, Optional, Regexp
from .models import User # Import User to check for existing usernames/emails if needed

# --- Auth Forms ---
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=80)])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Login')

class SignupForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=80)])
    # email = StringField('Email', validators=[DataRequired(), Email()]) # Add email if needed
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password', message='Passwords must match.')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.get_by_username(username.data)
        if user:
            raise ValidationError('Username already taken. Please choose a different one.')

    # def validate_email(self, email):
    #     user = mongo.db.users.find_one({'email': email.data}) # Assuming email field exists
    #     if user:
    #         raise ValidationError('Email address already registered.')

# --- Vault Item Forms ---
class ServerForm(FlaskForm):
    server_name = StringField('Server Name/Identifier', validators=[DataRequired(), Length(max=100)])
    ip_address = StringField('IP Address/Hostname', validators=[Optional(), Length(max=100)])
    login_as = StringField('Login As (Username)', validators=[DataRequired(), Length(max=100)])
    password = PasswordField('Password', validators=[
        Optional(), # Optional only on edit, required on add (handle in view)
        Length(min=6, message='Password should be at least 6 characters long.')
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        EqualTo('password', message='Passwords must match.')
        # Make this validator conditional based on whether password is being set
    ])
    notes = TextAreaField('Notes', validators=[Optional(), Length(max=1000)])
    submit = SubmitField('Save Server')

class LaptopForm(FlaskForm):
    laptop_id = StringField('Laptop ID / Asset Tag', validators=[DataRequired(), Length(max=100)])
    employee_name = StringField('Employee Name', validators=[DataRequired(), Length(max=100)])
    username = StringField('Laptop Login Username', validators=[DataRequired(), Length(max=100)])
    password = PasswordField('Password', validators=[
        Optional(), # Optional on edit
        Length(min=6, message='Password should be at least 6 characters long.')
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        EqualTo('password', message='Passwords must match.')
    ])
    installed_software = TextAreaField('Installed Software (comma-separated)', validators=[Optional(), Length(max=2000)])
    notes = TextAreaField('Notes', validators=[Optional(), Length(max=1000)])
    submit = SubmitField('Save Laptop')

    # Add validation to ensure laptop_id is unique if needed (check DB in view or here)

class PersonalPasswordForm(FlaskForm):
    website_or_service = StringField('Website / Service Name', validators=[DataRequired(), Length(max=150)])
    username = StringField('Username / Email', validators=[DataRequired(), Length(max=150)])
    password = PasswordField('Password', validators=[
        Optional(), # Optional on edit
        Length(min=6, message='Password should be at least 6 characters long.')
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        EqualTo('password', message='Passwords must match.')
    ])
    notes = TextAreaField('Notes', validators=[Optional(), Length(max=1000)])
    submit = SubmitField('Save Password')


# --- Admin Forms ---
class TemporaryAccessForm(FlaskForm):
    user_id = SelectField('Select User', coerce=str, validators=[DataRequired()])
    # Add expiry option - using DateTimeLocalField for modern browsers
    expiry_datetime = DateTimeLocalField('Grant Access Until (Optional, UTC)', format='%Y-%m-%dT%H:%M', validators=[Optional()])
    submit = SubmitField('Grant Temporary Admin Access')

    # Add revoke option later if needed, maybe on a different form/button