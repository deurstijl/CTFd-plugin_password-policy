from CTFd.plugins import register_plugin_asset, register_plugin_assets_directory, override_template
from CTFd.plugins import bypass_csrf_protection
from CTFd.utils.decorators import admins_only
from flask import request, Blueprint, jsonify, abort, render_template, url_for, redirect, session
# from wtforms import TextField, SubmitField, BooleanField, HiddenField, FileField, SelectMultipleField
from CTFd.utils.dates import unix_time
from datetime import datetime
import json
from CTFd.utils import get_config, set_config
from CTFd.utils.plugins import register_script as utils_register_plugin_script
from CTFd.utils.user import is_admin

from flask import flash
import re

def define_docker_admin(app):
    admin_password_policy = Blueprint('admin_password_policy', __name__, template_folder='templates',
                                    static_folder='assets')

    @admin_password_policy.route("/admin/password_policy", methods=["GET", "POST"])
    @bypass_csrf_protection
    @admins_only
    def config():
        if request.method == "POST":
            policy = {
                "require_upper": 'require_upper' in request.form,
                "require_lower": 'require_lower' in request.form,
                "require_number": 'require_number' in request.form,
                "require_symbol": 'require_symbol' in request.form,
                "min_length": int(request.form.get('min_length', 12))
            }
            set_config("password_policy", json.dumps(policy))
            flash("Password policy updated successfully.", "success")
            return redirect(url_for('admin_password_policy.config'))

        policy = get_policy_config()
        return render_template("password_policy_config.html", policy=policy)

    @admin_password_policy.route("/files/password_policy.json", methods=["GET"])
    def policy_json():
        return jsonify(get_policy_config())

    def get_policy_config():
        raw = get_config("password_policy")
        if raw:
            return json.loads(raw)
        return {
            "require_upper": True,
            "require_lower": True,
            "require_number": True,
            "require_symbol": True,
            "min_length": 12
        }
    app.register_blueprint(admin_password_policy)

def check_password_policy(password):
    raw = get_config("password_policy")
    policy = json.loads(raw) if raw else {}

    if policy.get('require_upper') and not re.search(r'[A-Z]', password):
        return False, "Password must include an uppercase letter."
    if policy.get('require_lower') and not re.search(r'[a-z]', password):
        return False, "Password must include a lowercase letter."
    if policy.get('require_number') and not re.search(r'\d', password):
        return False, "Password must include a number."
    if policy.get('require_symbol') and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must include a symbol."
    if len(password) < policy.get('min_length', 8):
        return False, f"Password must be at least {policy.get('min_length', 8)} characters long."
    return True, ""

def inject_into_routes(app):
    @app.before_request
    def enforce_password_policy():
        # Only intercept requests where password is being set
        if request.method not in ['POST', 'PATCH']:
            return

        endpoint = request.endpoint or ""
        if endpoint=="api.users_user_private":
            try:
                data = request.get_json()
                password = data.get("password")
                if password and password !="":
                    valid, msg = check_password_policy(password)
                    if not valid:
                        abort(400, description=msg)
                else:
                    # the password field is the "new password."
                    # if this is empty we're not setting it, so we return
                    return
            except Exception as e:
                abort(400, description="Password policy validation failed.") 
        
        elif endpoint=="auth.register":
            try:
                password = request.form.get("password")
                if password:
                    valid, msg = check_password_policy(password)
                    if not valid:
                        abort(400, description=msg)
                else:
                    abort(400, description="No Password field discovered")
            except Exception as e:
                abort(400, description="Password policy validation failed.")

        elif endpoint=="auth.reset_password" and request.form.get("password"):
            password = request.form.get("password")
            valid, msg = check_password_policy(password)
            if not valid:
                abort(400, description=msg)
        
def load(app):
    register_plugin_assets_directory(app, base_path='/plugins/password_policy/assets')
    # This line injects the JS globally into every page
    register_plugin_asset(app, asset_path="/plugins/password_policy/assets/password-policy.js")
    #from IPython import embed;embed()
    utils_register_plugin_script('/plugins/password_policy/assets/password-policy.js')
    app.db.create_all()
    define_docker_admin(app)
    inject_into_routes(app)