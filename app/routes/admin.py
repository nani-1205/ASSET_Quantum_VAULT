from flask import Blueprint, render_template, redirect, url_for, flash, request, abort, send_file, make_response
from flask_login import login_required, current_user
from ..forms import ServerForm, LaptopForm, TemporaryAccessForm
from ..models import (
    User, add_server, get_all_servers, get_server_by_id, update_server, delete_server,
    add_laptop, get_all_laptops, get_laptop_by_id, update_laptop, delete_laptop
)
from ..utils import admin_required, generate_xlsx_report, generate_pdf_report, temp_admin_check
from datetime import datetime, timezone, timedelta
from wtforms.validators import DataRequired, Length, EqualTo, Optional

admin_bp = Blueprint('admin', __name__)

# Apply admin_required decorator to all routes in this blueprint
@admin_bp.before_request
@login_required
@admin_required # Ensures only admin or temp admin can access these routes
@temp_admin_check # Checks temp admin status validity on each request
def before_request():
    """ Protect all admin routes """
    pass

@admin_bp.route('/dashboard')
def admin_dashboard():
    servers = get_all_servers()
    laptops = get_all_laptops()
    return render_template('admin_dashboard.html', title='Admin Dashboard', servers=servers, laptops=laptops)

# --- Server Management ---
@admin_bp.route('/servers')
def view_servers():
    servers = get_all_servers()
    return render_template('view_servers.html', title='View Servers', servers=servers)

@admin_bp.route('/servers/add', methods=['GET', 'POST'])
def add_server_route():
    form = ServerForm()
    # Password is required for adding
    form.password.validators = [DataRequired(message="Password is required."), Length(min=6)]
    form.confirm_password.validators = [DataRequired(), EqualTo('password', message='Passwords must match.')]

    if form.validate_on_submit():
        success = add_server(
            server_name=form.server_name.data,
            ip_address=form.ip_address.data,
            login_as=form.login_as.data,
            password=form.password.data,
            notes=form.notes.data,
            created_by_id=current_user.id
        )
        if success:
            flash('Server added successfully!', 'success')
            return redirect(url_for('admin.view_servers'))
        else:
            flash('Failed to add server. Encryption might have failed.', 'danger')
    return render_template('add_edit_server.html', title='Add Server', form=form, form_action=url_for('admin.add_server_route'))


@admin_bp.route('/servers/edit/<server_id>', methods=['GET', 'POST'])
def edit_server_route(server_id):
    server_item = get_server_by_id(server_id)
    if not server_item:
        flash('Server not found.', 'danger')
        return redirect(url_for('admin.view_servers'))

    form = ServerForm(data=server_item)
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
                'server_name': form.server_name.data,
                'ip_address': form.ip_address.data,
                'login_as': form.login_as.data,
                'notes': form.notes.data,
            }
            if form.password.data: # Only include password if it was entered
                update_data['password'] = form.password.data

            success = update_server(server_id, update_data)
            if success:
                flash('Server updated successfully!', 'success')
                return redirect(url_for('admin.view_servers'))
            else:
                flash('Failed to update server. Encryption or database error occurred.', 'danger')

    # Clear password fields before rendering edit form
    form.password.data = ""
    form.confirm_password.data = ""
    return render_template('add_edit_server.html', title='Edit Server', form=form, form_action=url_for('admin.edit_server_route', server_id=server_id))

@admin_bp.route('/servers/delete/<server_id>', methods=['POST'])
def delete_server_route(server_id):
    success = delete_server(server_id)
    if success:
        flash('Server deleted successfully!', 'success')
    else:
        flash('Failed to delete server.', 'danger')
    return redirect(url_for('admin.view_servers'))


# --- Laptop Management ---
@admin_bp.route('/laptops')
def view_laptops():
    laptops = get_all_laptops()
    return render_template('view_laptops.html', title='View Laptops', laptops=laptops)

@admin_bp.route('/laptops/add', methods=['GET', 'POST'])
def add_laptop_route():
    form = LaptopForm()
    # Password required for adding
    form.password.validators = [DataRequired(message="Password is required."), Length(min=6)]
    form.confirm_password.validators = [DataRequired(), EqualTo('password', message='Passwords must match.')]
    # Handle software list - split comma separated string into list
    software_list = [s.strip() for s in form.installed_software.data.split(',') if s.strip()] if form.installed_software.data else []

    if form.validate_on_submit():
        success = add_laptop(
            laptop_id_str=form.laptop_id.data,
            employee_name=form.employee_name.data,
            username=form.username.data,
            password=form.password.data,
            installed_software=software_list,
            notes=form.notes.data,
            created_by_id=current_user.id
        )
        if success:
            flash('Laptop added successfully!', 'success')
            return redirect(url_for('admin.view_laptops'))
        else:
            flash('Failed to add laptop. Encryption might have failed.', 'danger')
    return render_template('add_edit_laptop.html', title='Add Laptop', form=form, form_action=url_for('admin.add_laptop_route'))

@admin_bp.route('/laptops/edit/<laptop_id>', methods=['GET', 'POST'])
def edit_laptop_route(laptop_id):
    laptop_item = get_laptop_by_id(laptop_id)
    if not laptop_item:
        flash('Laptop not found.', 'danger')
        return redirect(url_for('admin.view_laptops'))

    # Prepare data for form: join software list back into comma-separated string
    laptop_item['installed_software'] = ', '.join(laptop_item.get('installed_software', []))
    form = LaptopForm(data=laptop_item)
     # Make password optional on edit
    form.password.validators = [Optional(), Length(min=6)]
    form.confirm_password.validators = [Optional(), EqualTo('password', message='Passwords must match.')]

    if form.validate_on_submit():
         # Check password confirmation logic
        if form.password.data and not form.confirm_password.data:
             form.confirm_password.errors.append('Please confirm the new password.')
        elif form.password.data != form.confirm_password.data:
             form.confirm_password.errors.append('Passwords must match.')
        else:
            update_data = {
                'laptop_id': form.laptop_id.data,
                'employee_name': form.employee_name.data,
                'username': form.username.data,
                'installed_software': form.installed_software.data, # Will be processed in update_laptop
                'notes': form.notes.data,
            }
            if form.password.data:
                update_data['password'] = form.password.data

            success = update_laptop(laptop_id, update_data)
            if success:
                flash('Laptop updated successfully!', 'success')
                return redirect(url_for('admin.view_laptops'))
            else:
                flash('Failed to update laptop.', 'danger')

    # Clear password fields before rendering edit form
    form.password.data = ""
    form.confirm_password.data = ""
    return render_template('add_edit_laptop.html', title='Edit Laptop', form=form, form_action=url_for('admin.edit_laptop_route', laptop_id=laptop_id))


@admin_bp.route('/laptops/delete/<laptop_id>', methods=['POST'])
def delete_laptop_route(laptop_id):
    success = delete_laptop(laptop_id)
    if success:
        flash('Laptop deleted successfully!', 'success')
    else:
        flash('Failed to delete laptop.', 'danger')
    return redirect(url_for('admin.view_laptops'))

# --- Temporary Access ---
@admin_bp.route('/temporary_access', methods=['GET', 'POST'])
def temporary_access():
    if not current_user.is_admin: # Only permanent admins can grant temporary access
        flash('Only permanent administrators can grant temporary access.', 'warning')
        return redirect(url_for('admin.admin_dashboard'))

    form = TemporaryAccessForm()
    # Populate user choices dynamically, excluding the current admin and existing admins
    users = User.get_all_users()
    form.user_id.choices = [
        (user.id, user.username) for user in users
        if user.id != current_user.id and not user.is_admin # Cannot grant to self or other admins
    ]

    if request.method == 'POST': # Using request.method check because validate_on_submit might fail if choices are empty
       selected_user_id = form.user_id.data
       user_to_grant = User.get_by_id(selected_user_id)

       if not user_to_grant:
           flash('Selected user not found.', 'danger')
       elif user_to_grant.is_admin:
           flash('Cannot grant temporary access to a permanent admin.', 'warning')
       elif form.validate_on_submit(): # Now validate the rest of the form
            expiry_dt = None
            if form.expiry_datetime.data:
                try:
                    # Ensure the naive datetime from form is treated as UTC
                    naive_dt = form.expiry_datetime.data
                    expiry_dt = naive_dt.replace(tzinfo=timezone.utc)
                    if expiry_dt <= datetime.now(timezone.utc):
                         flash('Expiry time must be in the future.', 'warning')
                         return render_template('temporary_access.html', title='Grant Temporary Access', form=form)
                except Exception as e:
                    flash(f'Invalid date/time format: {e}', 'danger')
                    return render_template('temporary_access.html', title='Grant Temporary Access', form=form)

            user_to_grant.grant_temp_admin(expiry_dt)
            flash(f'Temporary admin access granted to {user_to_grant.username}.', 'success')
            if expiry_dt:
                flash(f'Access expires at {expiry_dt.strftime("%Y-%m-%d %H:%M:%S %Z")}', 'info')
            else:
                flash('Access granted indefinitely until manually revoked.', 'info')
            return redirect(url_for('admin.admin_dashboard'))
       else:
            # Handle validation errors if validate_on_submit fails after checks
             flash('Please correct the errors below.', 'danger')


    # Also list users currently having temporary access
    temp_admins = [user for user in users if user.is_temp_admin]

    return render_template('temporary_access.html', title='Grant Temporary Access', form=form, temp_admins=temp_admins)


@admin_bp.route('/revoke_temporary_access/<user_id>', methods=['POST'])
def revoke_temporary_access(user_id):
    if not current_user.is_admin:
        flash('Only permanent administrators can revoke temporary access.', 'warning')
        abort(403)

    user_to_revoke = User.get_by_id(user_id)
    if user_to_revoke and user_to_revoke.is_temp_admin:
        user_to_revoke.revoke_temp_admin()
        flash(f'Temporary admin access revoked for {user_to_revoke.username}.', 'success')
    elif user_to_revoke:
         flash(f'{user_to_revoke.username} does not have temporary access.', 'warning')
    else:
        flash('User not found.', 'danger')
    return redirect(url_for('admin.temporary_access'))


# --- Reporting ---
@admin_bp.route('/report/software', methods=['GET'])
def software_report():
    report_format = request.args.get('format', 'xlsx').lower() # Default to xlsx
    laptops_data = get_all_laptops() # Get raw data

    if not laptops_data:
        flash('No laptop data available to generate a report.', 'warning')
        return redirect(url_for('admin.admin_dashboard'))

    try:
        if report_format == 'xlsx':
            buffer = generate_xlsx_report(laptops_data)
            filename = "laptop_software_report.xlsx"
            mimetype = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        elif report_format == 'pdf':
            buffer = generate_pdf_report(laptops_data)
            filename = "laptop_software_report.pdf"
            mimetype = "application/pdf"
        else:
            flash('Invalid report format requested.', 'danger')
            return redirect(url_for('admin.admin_dashboard'))

        response = make_response(send_file(
            buffer,
            mimetype=mimetype,
            as_attachment=True,
            download_name=filename # Use download_name modern Flask versions
            # attachment_filename=filename # Older Flask versions
        ))
        response.headers["Content-Disposition"] = f"attachment; filename={filename}"
        return response

    except ImportError as e:
         flash(f"Reporting library not installed. Please install 'openpyxl' for XLSX or 'reportlab' for PDF. Error: {e}", "danger")
         return redirect(url_for('admin.admin_dashboard'))
    except Exception as e:
        flash(f'An error occurred while generating the report: {e}', 'danger')
        # Log the error e
        print(f"Report generation error: {e}")
        return redirect(url_for('admin.admin_dashboard'))