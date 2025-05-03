from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify, abort
from flask_login import login_required, current_user
from ..models import (
    get_personal_passwords_for_user, add_personal_password,
    get_personal_password_by_id, update_personal_password, delete_personal_password,
    get_decrypted_password
)
from ..forms import PersonalPasswordForm
from ..utils import admin_required, temp_admin_check # Import temp_admin_check

main_bp = Blueprint('main', __name__)

@main_bp.route('/dashboard')
@login_required
@temp_admin_check # Check temp admin status on accessing dashboard
def index():
    user_is_admin = current_user.is_admin_or_temp()

    if user_is_admin:
        # Admins might see a combined or specific admin dashboard
        # Redirecting to admin dashboard for clarity
        return redirect(url_for('admin.admin_dashboard'))
    else:
        # Regular user dashboard
        personal_passwords = get_personal_passwords_for_user(current_user.id)
        return render_template('user_dashboard.html', title='Your Dashboard', personal_passwords=personal_passwords)

# --- Personal Password Management ---

@main_bp.route('/personal/add', methods=['GET', 'POST'])
@login_required
@temp_admin_check
def add_personal():
    form = PersonalPasswordForm()
    # Password is required for adding
    form.password.validators = [DataRequired(message="Password is required."), Length(min=6)]
    form.confirm_password.validators = [DataRequired(), EqualTo('password', message='Passwords must match.')]

    if form.validate_on_submit():
        success = add_personal_password(
            user_id=current_user.id,
            website=form.website_or_service.data,
            username=form.username.data,
            password=form.password.data,
            notes=form.notes.data
        )
        if success:
            flash('Personal password added successfully!', 'success')
            return redirect(url_for('main.index'))
        else:
            flash('Failed to add password. Encryption might have failed.', 'danger')
    return render_template('add_edit_personal.html', title='Add Personal Password', form=form, form_action=url_for('main.add_personal'))

@main_bp.route('/personal/edit/<password_id>', methods=['GET', 'POST'])
@login_required
@temp_admin_check
def edit_personal(password_id):
    pw_item = get_personal_password_by_id(password_id, current_user.id)
    if not pw_item:
        flash('Password not found or you do not have permission.', 'danger')
        return redirect(url_for('main.index'))

    form = PersonalPasswordForm(data=pw_item) # Pre-populate form
    # Make password optional on edit
    form.password.validators = [Optional(), Length(min=6)]
    form.confirm_password.validators = [Optional(), EqualTo('password', message='Passwords must match.')]


    if form.validate_on_submit():
         # Check if password field has input, if so, require confirmation
        if form.password.data and not form.confirm_password.data:
             form.confirm_password.errors.append('Please confirm the new password.')
        elif form.password.data != form.confirm_password.data:
             form.confirm_password.errors.append('Passwords must match.')
        else:
             update_data = {
                'website_or_service': form.website_or_service.data,
                'username': form.username.data,
                'notes': form.notes.data
            }
             if form.password.data: # Only include password if it was entered
                update_data['password'] = form.password.data

             success = update_personal_password(password_id, current_user.id, update_data)
             if success:
                flash('Personal password updated successfully!', 'success')
                return redirect(url_for('main.index'))
             else:
                flash('Failed to update password. Encryption or database error occurred.', 'danger')

    # Clear password fields before rendering edit form for security
    form.password.data = ""
    form.confirm_password.data = ""
    return render_template('add_edit_personal.html', title='Edit Personal Password', form=form, form_action=url_for('main.edit_personal', password_id=password_id))

@main_bp.route('/personal/delete/<password_id>', methods=['POST'])
@login_required
@temp_admin_check
def delete_personal(password_id):
    # Add CSRF token check if using direct POST links without forms
    success = delete_personal_password(password_id, current_user.id)
    if success:
        flash('Personal password deleted successfully!', 'success')
    else:
        flash('Failed to delete password or password not found.', 'danger')
    return redirect(url_for('main.index'))


# --- Password Reveal/Copy ---
# This endpoint reveals the password server-side.
# Use JavaScript for client-side copying for better UX.
@main_bp.route('/get_password/<item_type>/<item_id>', methods=['GET'])
@login_required
@temp_admin_check
def get_password(item_type, item_id):
    user_id = None
    is_admin = current_user.is_admin_or_temp()

    if item_type == 'personal':
        user_id = current_user.id
    elif item_type in ['server', 'laptop'] and not is_admin:
         # Only admins/temp admins can view server/laptop passwords
        abort(403) # Forbidden

    decrypted_password = get_decrypted_password(item_type, item_id, user_id)

    if decrypted_password is not None:
        # Return as JSON - the frontend JS will handle displaying/copying
        return jsonify({'password': decrypted_password})
    else:
        # Password not found, decryption failed, or permission denied
        return jsonify({'error': 'Could not retrieve password.'}), 404 # Or 403?