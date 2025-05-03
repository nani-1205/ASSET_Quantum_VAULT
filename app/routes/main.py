from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify, abort
from flask_login import login_required, current_user
# --- Added WTForms Validator Import ---
from wtforms.validators import DataRequired, Length, EqualTo, Optional
# --- End Added Import ---
from ..models import (
    get_personal_passwords_for_user, add_personal_password,
    get_personal_password_by_id, update_personal_password, delete_personal_password,
    get_decrypted_password
)
from ..forms import PersonalPasswordForm
from ..utils import admin_required, temp_admin_check # Import temp_admin_check

main_bp = Blueprint('main', __name__)

@main_bp.route('/dashboard') # Changed to /dashboard as primary entry after login
@login_required
@temp_admin_check # Check temp admin status on accessing dashboard
def index():
    # Determine user role *after* checking temp status expiry
    user_is_admin = current_user.is_admin_or_temp()

    if user_is_admin:
        # Admins are redirected to the specific admin dashboard
        return redirect(url_for('admin.admin_dashboard'))
    else:
        # Regular user dashboard shows personal passwords
        personal_passwords = get_personal_passwords_for_user(current_user.id)
        print(f"--- [main.py] User {current_user.username} dashboard: Found {len(personal_passwords)} personal passwords.") # Debug
        return render_template('user_dashboard.html', title='Your Dashboard', personal_passwords=personal_passwords)

# --- Personal Password Management ---

@main_bp.route('/personal/add', methods=['GET', 'POST'])
@login_required
@temp_admin_check
def add_personal():
    form = PersonalPasswordForm()
    # Password is required for adding - Apply validators directly here
    # These validators are now defined because of the import added above
    form.password.validators = [DataRequired(message="Password is required."), Length(min=6)]
    form.confirm_password.validators = [DataRequired(), EqualTo('password', message='Passwords must match.')]

    if form.validate_on_submit():
        print(f"--- [main.py] Attempting to add personal password for user {current_user.username}.") # Debug
        success = add_personal_password(
            user_id=current_user.id,
            website=form.website_or_service.data,
            username=form.username.data,
            password=form.password.data,
            notes=form.notes.data
        )
        if success:
            print(f"--- [main.py] Personal password added successfully for user {current_user.username}.") # Debug
            flash('Personal password added successfully!', 'success')
            return redirect(url_for('main.index')) # Redirect to user dashboard
        else:
            print(f"--- [main.py] ERROR: Failed to add personal password for user {current_user.username}.") # Debug
            flash('Failed to add password. Encryption or database error might have occurred.', 'danger')
            
    # If GET request or validation fails, render the template
    return render_template('add_edit_personal.html', title='Add Personal Password', form=form, form_action=url_for('main.add_personal'))


@main_bp.route('/personal/edit/<password_id>', methods=['GET', 'POST'])
@login_required
@temp_admin_check
def edit_personal(password_id):
    pw_item = get_personal_password_by_id(password_id, current_user.id)
    if not pw_item:
        flash('Password not found or you do not have permission.', 'danger')
        return redirect(url_for('main.index'))

    # Pre-populate form, but clear password fields for security
    form = PersonalPasswordForm(data=pw_item)
    form.password.data = "" # Clear password field
    form.confirm_password.data = "" # Clear confirm field

    # Make password optional on edit - these validators are now defined
    form.password.validators = [Optional(), Length(min=6)]
    form.confirm_password.validators = [Optional(), EqualTo('password', message='Passwords must match.')]


    if form.validate_on_submit():
         print(f"--- [main.py] Attempting to update personal password {password_id} for user {current_user.username}.") # Debug
         # Check if password field has input, if so, require confirmation
         if form.password.data and not form.confirm_password.data:
             form.confirm_password.errors.append('Please confirm the new password.')
             flash('Please confirm the new password.', 'warning') # Flash message for user
         elif form.password.data != form.confirm_password.data:
             # This check might be redundant if EqualTo validator works, but good safeguard
             form.confirm_password.errors.append('Passwords must match.')
             flash('Passwords do not match.', 'warning') # Flash message for user
         else:
             # Validation passed or password wasn't being changed
             update_data = {
                'website_or_service': form.website_or_service.data,
                'username': form.username.data,
                'notes': form.notes.data
             }
             if form.password.data: # Only include password if it was entered
                update_data['password'] = form.password.data

             success = update_personal_password(password_id, current_user.id, update_data)
             if success:
                print(f"--- [main.py] Personal password {password_id} updated successfully for user {current_user.username}.") # Debug
                flash('Personal password updated successfully!', 'success')
                return redirect(url_for('main.index'))
             else:
                print(f"--- [main.py] ERROR: Failed to update personal password {password_id} for user {current_user.username}.") # Debug
                flash('Failed to update password. Encryption or database error occurred.', 'danger')
    # Else block for validation errors is implicitly handled by re-rendering the template below

    # Render template on GET or if validation fails on POST
    return render_template('add_edit_personal.html', title='Edit Personal Password', form=form, form_action=url_for('main.edit_personal', password_id=password_id))

@main_bp.route('/personal/delete/<password_id>', methods=['POST'])
@login_required
@temp_admin_check
def delete_personal(password_id):
    # Add CSRF token check if using direct POST links without forms (WTForms handles it in form submissions)
    print(f"--- [main.py] Attempting to delete personal password {password_id} for user {current_user.username}.") # Debug
    success = delete_personal_password(password_id, current_user.id)
    if success:
        print(f"--- [main.py] Personal password {password_id} deleted successfully for user {current_user.username}.") # Debug
        flash('Personal password deleted successfully!', 'success')
    else:
        print(f"--- [main.py] ERROR: Failed to delete personal password {password_id} for user {current_user.username}.") # Debug
        flash('Failed to delete password or password not found.', 'danger')
    return redirect(url_for('main.index')) # Redirect back to user dashboard


# --- Password Reveal/Copy ---
# This endpoint reveals the password server-side.
# Use JavaScript for client-side copying for better UX.
@main_bp.route('/get_password/<item_type>/<item_id>', methods=['GET'])
@login_required
@temp_admin_check
def get_password(item_type, item_id):
    user_id = None
    is_admin = current_user.is_admin_or_temp()
    print(f"--- [main.py] Request to get password for type '{item_type}', ID '{item_id}' by user {current_user.username} (is_admin={is_admin}).") # Debug

    if item_type == 'personal':
        user_id = current_user.id
    elif item_type in ['server', 'laptop'] and not is_admin:
         # Only admins/temp admins can view server/laptop passwords
         print(f"--- [main.py] Access denied for user {current_user.username} to get non-personal password.") # Debug
         abort(403) # Forbidden

    decrypted_password = get_decrypted_password(item_type, item_id, user_id)

    if decrypted_password is not None:
        # Return as JSON - the frontend JS will handle displaying/copying
        print(f"--- [main.py] Successfully decrypted password for {item_type} {item_id}.") # Debug
        return jsonify({'password': decrypted_password})
    else:
        # Password not found, decryption failed, or permission denied
        print(f"--- [main.py] Failed to decrypt password for {item_type} {item_id}.") # Debug
        return jsonify({'error': 'Could not retrieve password.'}), 404 # Or 403?