import traceback
# --- Make sure request is imported ---
from flask import request, Blueprint, render_template, redirect, url_for, flash, abort, send_file, make_response
# --- End Import Check ---
from flask_login import login_required, current_user
from ..forms import ServerForm, LaptopForm, TemporaryAccessForm
from ..models import (
    User, add_server, get_all_servers, get_server_by_id, update_server, delete_server,
    add_laptop, get_all_laptops, get_laptop_by_id, update_laptop, delete_laptop,
    get_laptops_by_ids
)
from ..utils import admin_required, generate_xlsx_report, generate_pdf_report, temp_admin_check
from datetime import datetime, timezone, timedelta
from wtforms.validators import DataRequired, Length, EqualTo, Optional

admin_bp = Blueprint('admin', __name__)

@admin_bp.before_request
@login_required
@admin_required
@temp_admin_check
def before_request():
    """ Protect all admin routes """
    pass

@admin_bp.route('/dashboard')
def admin_dashboard():
    try:
        servers = get_all_servers()
        laptops = get_all_laptops()
    except Exception as e:
        print(f"--- [admin.py] ERROR fetching data for admin dashboard: {e}")
        flash("Error loading dashboard data. Please check database connection.", "danger")
        servers = []
        laptops = []
    return render_template('admin_dashboard.html', title='Admin Dashboard', servers=servers, laptops=laptops)

# --- Server Management ---
# --- MODIFIED view_servers ---
@admin_bp.route('/servers')
def view_servers():
    # Get search query from URL parameters (e.g., /servers?search=web)
    search_query = request.args.get('search', '').strip() # Get query, default to empty, strip whitespace
    print(f"--- [admin.py] Viewing servers with search: '{search_query}'") # Debug
    try:
        servers = get_all_servers(search_query=search_query)
    except Exception as e:
        print(f"--- [admin.py] ERROR searching servers: {e}")
        flash("An error occurred while searching servers.", "danger")
        servers = [] # Return empty list on error
    # Pass the search query back to the template to keep it in the input box
    return render_template('view_servers.html', title='View Servers', servers=servers, search_query=search_query)

@admin_bp.route('/servers/add', methods=['GET', 'POST'])
def add_server_route():
    form = ServerForm()
    form.password.validators = [DataRequired(message="Password is required."), Length(min=6)]
    form.confirm_password.validators = [DataRequired(), EqualTo('password', message='Passwords must match.')]
    if form.validate_on_submit():
        print(f"--- [admin.py] Attempting to add server '{form.server_name.data}' by user {current_user.username}.")
        success = add_server(
            server_name=form.server_name.data, ip_address=form.ip_address.data, login_as=form.login_as.data,
            password=form.password.data, notes=form.notes.data, created_by_id=current_user.id
        )
        if success:
            flash('Server added successfully!', 'success')
            return redirect(url_for('admin.view_servers'))
        else:
            print(f"--- [admin.py] ERROR adding server '{form.server_name.data}'.")
            flash('Failed to add server. Encryption or database error might have occurred.', 'danger')
    elif request.method == 'POST':
         print("--- [admin.py] Server add form validation failed.")
         flash('Please correct the errors below.', 'danger')
    return render_template('add_edit_server.html', title='Add Server', form=form, form_action=url_for('admin.add_server_route'))

@admin_bp.route('/servers/edit/<server_id>', methods=['GET', 'POST'])
def edit_server_route(server_id):
    server_item = get_server_by_id(server_id)
    if not server_item:
        flash('Server not found.', 'danger')
        return redirect(url_for('admin.view_servers'))
    form = ServerForm(data=server_item)
    form.password.validators = [Optional(), Length(min=6)]
    form.confirm_password.validators = [Optional(), EqualTo('password', message='Passwords must match.')]
    if form.validate_on_submit():
        print(f"--- [admin.py] Attempting to update server ID {server_id} by user {current_user.username}.")
        if form.password.data and not form.confirm_password.data:
             form.confirm_password.errors.append('Please confirm the new password.')
             flash('Please confirm the new password.', 'warning')
        elif form.password.data != form.confirm_password.data:
             form.confirm_password.errors.append('Passwords must match.')
             flash('Passwords do not match.', 'warning')
        else:
            update_data = {
                'server_name': form.server_name.data, 'ip_address': form.ip_address.data,
                'login_as': form.login_as.data, 'notes': form.notes.data,
            }
            if form.password.data: update_data['password'] = form.password.data
            success = update_server(server_id, update_data)
            if success:
                flash('Server updated successfully!', 'success')
                return redirect(url_for('admin.view_servers'))
            else:
                print(f"--- [admin.py] ERROR updating server ID {server_id}.")
                flash('Failed to update server. Encryption or database error occurred.', 'danger')
    elif request.method == 'POST':
         print(f"--- [admin.py] Server edit form validation failed for ID {server_id}.")
         flash('Please correct the errors below.', 'danger')
    form.password.data = ""
    form.confirm_password.data = ""
    return render_template('add_edit_server.html', title='Edit Server', form=form, form_action=url_for('admin.edit_server_route', server_id=server_id))

@admin_bp.route('/servers/delete/<server_id>', methods=['POST'])
def delete_server_route(server_id):
    print(f"--- [admin.py] Attempting to delete server ID {server_id} by user {current_user.username}.")
    success = delete_server(server_id)
    if success: flash('Server deleted successfully!', 'success')
    else: flash('Failed to delete server.', 'danger')
    return redirect(url_for('admin.view_servers'))


# --- Laptop Management ---
# --- MODIFIED view_laptops ---
@admin_bp.route('/laptops')
def view_laptops():
    # Get search query from URL parameters
    search_query = request.args.get('search', '').strip()
    print(f"--- [admin.py] Viewing laptops with search: '{search_query}'") # Debug
    try:
        laptops = get_all_laptops(search_query=search_query)
    except Exception as e:
        print(f"--- [admin.py] ERROR searching laptops: {e}")
        flash("An error occurred while searching laptops.", "danger")
        laptops = [] # Return empty list on error
    # Pass the search query back to the template
    return render_template('view_laptops.html', title='View Laptops', laptops=laptops, search_query=search_query)


@admin_bp.route('/laptops/add', methods=['GET', 'POST'])
def add_laptop_route():
    form = LaptopForm()
    form.password.validators = [DataRequired(message="Password is required."), Length(min=6)]
    form.confirm_password.validators = [DataRequired(), EqualTo('password', message='Passwords must match.')]
    if form.validate_on_submit():
        print(f"--- [admin.py] Attempting to add laptop '{form.laptop_id.data}' by user {current_user.username}.")
        software_list = [s.strip() for s in form.installed_software.data.split(',') if s.strip()] if form.installed_software.data else []
        success = add_laptop(
            laptop_id_str=form.laptop_id.data, brand=form.brand.data,
            employee_name=form.employee_name.data, username=form.username.data,
            password=form.password.data, installed_software=software_list,
            notes=form.notes.data, created_by_id=current_user.id
        )
        if success:
            flash('Laptop added successfully!', 'success')
            return redirect(url_for('admin.view_laptops'))
        else:
            print(f"--- [admin.py] ERROR adding laptop '{form.laptop_id.data}'.")
            flash('Failed to add laptop. Encryption or database error might have occurred.', 'danger')
    elif request.method == 'POST':
         print("--- [admin.py] Laptop add form validation failed.")
         flash('Please correct the errors below.', 'danger')
    return render_template('add_edit_laptop.html', title='Add Laptop', form=form, form_action=url_for('admin.add_laptop_route'))

@admin_bp.route('/laptops/edit/<laptop_id>', methods=['GET', 'POST'])
def edit_laptop_route(laptop_id):
    laptop_item = get_laptop_by_id(laptop_id)
    if not laptop_item:
        flash('Laptop not found.', 'danger')
        return redirect(url_for('admin.view_laptops'))
    laptop_item_form_data = laptop_item.copy()
    laptop_item_form_data['installed_software'] = ', '.join(laptop_item.get('installed_software', []))
    form = LaptopForm(data=laptop_item_form_data)
    form.password.validators = [Optional(), Length(min=6)]
    form.confirm_password.validators = [Optional(), EqualTo('password', message='Passwords must match.')]
    if form.validate_on_submit():
        print(f"--- [admin.py] Attempting to update laptop ID {laptop_id} by user {current_user.username}.")
        if form.password.data and not form.confirm_password.data:
             form.confirm_password.errors.append('Please confirm the new password.')
             flash('Please confirm the new password.', 'warning')
        elif form.password.data != form.confirm_password.data:
             form.confirm_password.errors.append('Passwords must match.')
             flash('Passwords do not match.', 'warning')
        else:
            software_list = [s.strip() for s in form.installed_software.data.split(',') if s.strip()] if form.installed_software.data else []
            update_data = {
                'laptop_id': form.laptop_id.data, 'brand': form.brand.data,
                'employee_name': form.employee_name.data, 'username': form.username.data,
                'installed_software': software_list, 'notes': form.notes.data,
            }
            if form.password.data: update_data['password'] = form.password.data
            success = update_laptop(laptop_id, update_data)
            if success:
                flash('Laptop updated successfully!', 'success')
                return redirect(url_for('admin.view_laptops'))
            else:
                print(f"--- [admin.py] ERROR updating laptop ID {laptop_id}.")
                flash('Failed to update laptop. Encryption or database error occurred.', 'danger')
    elif request.method == 'POST':
         print(f"--- [admin.py] Laptop edit form validation failed for ID {laptop_id}.")
         flash('Please correct the errors below.', 'danger')
    form.password.data = ""
    form.confirm_password.data = ""
    return render_template('add_edit_laptop.html', title='Edit Laptop', form=form, form_action=url_for('admin.edit_laptop_route', laptop_id=laptop_id))

@admin_bp.route('/laptops/delete/<laptop_id>', methods=['POST'])
def delete_laptop_route(laptop_id):
    print(f"--- [admin.py] Attempting to delete laptop ID {laptop_id} by user {current_user.username}.")
    success = delete_laptop(laptop_id)
    if success: flash('Laptop deleted successfully!', 'success')
    else: flash('Failed to delete laptop.', 'danger')
    return redirect(url_for('admin.view_laptops'))

# --- Temporary Access ---
@admin_bp.route('/temporary_access', methods=['GET', 'POST'])
def temporary_access():
    if not current_user.is_admin:
        flash('Only permanent administrators can grant temporary access.', 'warning')
        return redirect(url_for('admin.admin_dashboard'))
    form = TemporaryAccessForm()
    users = User.get_all_users()
    form.user_id.choices = [(user.id, user.username) for user in users if user.id != current_user.id and not user.is_admin]
    if request.method == 'POST':
       selected_user_id = form.user_id.data
       user_to_grant = User.get_by_id(selected_user_id) if selected_user_id else None
       if not user_to_grant: flash('Selected user not found or invalid selection.', 'danger')
       elif user_to_grant.is_admin: flash('Cannot grant temporary access to a permanent admin.', 'warning')
       elif form.validate_on_submit():
            expiry_dt = None
            if form.expiry_datetime.data:
                try:
                    naive_dt = form.expiry_datetime.data
                    expiry_dt = naive_dt.replace(tzinfo=timezone.utc)
                    if expiry_dt <= datetime.now(timezone.utc):
                         flash('Expiry time must be in the future.', 'warning')
                         temp_admins = [user for user in User.get_all_users() if user.is_temp_admin]
                         return render_template('temporary_access.html', title='Grant Temporary Access', form=form, temp_admins=temp_admins)
                except Exception as e:
                    flash(f'Invalid date/time format: {e}', 'danger')
                    temp_admins = [user for user in User.get_all_users() if user.is_temp_admin]
                    return render_template('temporary_access.html', title='Grant Temporary Access', form=form, temp_admins=temp_admins)
            print(f"--- [admin.py] Granting temp access to {user_to_grant.username} by {current_user.username} until {expiry_dt}.")
            user_to_grant.grant_temp_admin(expiry_dt)
            flash(f'Temporary admin access granted to {user_to_grant.username}.', 'success')
            if expiry_dt: flash(f'Access expires at {expiry_dt.strftime("%Y-%m-%d %H:%M:%S %Z")}', 'info')
            else: flash('Access granted indefinitely until manually revoked.', 'info')
            return redirect(url_for('admin.temporary_access'))
       else:
             print(f"--- [admin.py] Temp access form validation failed.")
             flash('Please correct the errors below.', 'danger')
    temp_admins = [user for user in User.get_all_users() if user.is_temp_admin]
    return render_template('temporary_access.html', title='Grant Temporary Access', form=form, temp_admins=temp_admins)

@admin_bp.route('/revoke_temporary_access/<user_id>', methods=['POST'])
def revoke_temporary_access(user_id):
    if not current_user.is_admin:
        flash('Only permanent administrators can revoke temporary access.', 'warning')
        abort(403)
    user_to_revoke = User.get_by_id(user_id)
    if user_to_revoke and user_to_revoke.is_temp_admin:
        print(f"--- [admin.py] Revoking temp access for {user_to_revoke.username} by {current_user.username}.")
        user_to_revoke.revoke_temp_admin()
        flash(f'Temporary admin access revoked for {user_to_revoke.username}.', 'success')
    elif user_to_revoke: flash(f'{user_to_revoke.username} does not have temporary access.', 'warning')
    else: flash('User not found.', 'danger')
    return redirect(url_for('admin.temporary_access'))


# --- Reporting Route ---
@admin_bp.route('/report/software', methods=['GET', 'POST'])
def software_report():
    laptops_data = []
    report_format = 'xlsx'
    report_scope = "all" # Default scope

    if request.method == 'POST':
        selected_ids = request.form.getlist('selected_laptops')
        report_format = request.form.get('report_format', 'xlsx').lower()
        report_scope = "selected"
        print(f"--- [admin.py] Report requested for format: {report_format}")
        print(f"--- [admin.py] Selected laptop IDs: {selected_ids}")
        if not selected_ids:
            flash('No laptops selected for the report.', 'warning')
            return redirect(url_for('admin.view_laptops'))
        laptops_data = get_laptops_by_ids(selected_ids)
        report_title = f"Laptop Software Report (Selected {len(laptops_data)})"
    else: # GET Request
        report_format = request.args.get('format', 'xlsx').lower()
        print(f"--- [admin.py] Report requested for ALL laptops, format: {report_format}")
        laptops_data = get_all_laptops() # No search query needed here, get all for the report
        report_title = f"Laptop Software Report (All {len(laptops_data)})"

    if not laptops_data:
        flash('No laptop data found for the report criteria.', 'warning')
        if report_scope == 'selected': return redirect(url_for('admin.view_laptops'))
        else: return redirect(url_for('admin.admin_dashboard'))

    try:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        scope_tag = "All" if report_scope == "all" else "Selected"
        base_filename = f"Laptop_Software_{scope_tag}_{timestamp}"

        if report_format == 'xlsx':
            buffer = generate_xlsx_report(laptops_data)
            filename = f"{base_filename}.xlsx"
            mimetype = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        elif report_format == 'pdf':
            buffer = generate_pdf_report(laptops_data)
            filename = f"{base_filename}.pdf"
            mimetype = "application/pdf"
        else:
            flash('Invalid report format requested.', 'danger')
            if report_scope == 'selected': return redirect(url_for('admin.view_laptops'))
            else: return redirect(url_for('admin.admin_dashboard'))

        response = make_response(send_file(buffer, mimetype=mimetype, as_attachment=True, download_name=filename))
        return response
    except ImportError as e:
         print(f"--- [admin.py] Reporting library missing: {e}")
         flash(f"Reporting library not installed. Please install 'openpyxl' for XLSX or 'reportlab' for PDF. Error: {e}", "danger")
         if report_scope == 'selected': return redirect(url_for('admin.view_laptops'))
         else: return redirect(url_for('admin.admin_dashboard'))
    except Exception as e:
        flash(f'An error occurred while generating the report: {e}', 'danger')
        print(f"--- [admin.py] Report generation error: {e}")
        traceback.print_exc()
        if report_scope == 'selected': return redirect(url_for('admin.view_laptops'))
        else: return redirect(url_for('admin.admin_dashboard'))