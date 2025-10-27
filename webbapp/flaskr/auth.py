import functools
import os
import subprocess
import re

from flask import Blueprint, flash, g, redirect, render_template, request, session, url_for, Flask
from werkzeug.security import check_password_hash, generate_password_hash
from flaskr.db import get_db


bp = Blueprint('auth', __name__, url_prefix='/auth')
app = Flask(__name__)

@bp.route('/ping', methods=['GET'])
def ping_host():
    host = request.args.get('host')   # 1️⃣ ❌ Take user input directly (no validation)
    command = "ping -c 4 " + host     # 2️⃣ ❌ Construct the command with string concatenation (DANGEROUS)
    output = os.popen(command).read() # 3️⃣ ❌ Execute the command using os.popen (vulnerable to injection)
    # 4️⃣ Check if '4 received' appears in ping output (basic check)
    if "4 received" in output or "4 packets received" in output:
        #return "Reachable"
        return f"<pre>{output}</pre>"
    else:
        return "Unreachable"

# Apply subprocess run to avoid OS command injection via a diagnostics shell command, test
#  http://127.0.0.1:5000/auth/ping?host=127.0.0.1 
#  http://127.0.0.1:5000/auth/ping?host=localhost
@bp.route('/ping-secure', methods=['GET'])
def ping_host_secure():
    host = request.args.get('host')
    
    # Validate the input against a strict whitelist of allowed characters (e.g., for an IP address).
    # Using a regular expression to ensure the input is in a valid format for a hostname or IP.
    if not re.match(r'^[\w\d.-]+$', host):
        return "Error: Invalid host format.", 400
    
    # Use subprocess.run() with a list of arguments, not shell=True.
    # This ensures that the 'host' variable is passed as a literal argument to the 'ping' command
    # and is not interpreted by a system shell.
    try:
        result = subprocess.run(['ping', '-c', '4', host], capture_output=True, text=True, check=True)
        return f"<pre>{result.stdout}</pre>"
    except subprocess.CalledProcessError as e:
        # Handle cases where the ping command itself fails.
        return f"Error executing ping: {e}", 500

# index
@bp.route('/index')
def index():
    username = request.args.get('username')
    if username: 
        return render_template('auth/index.html')
    
# Simple list all products (safe read)
@bp.route('/products')
def products_list():
    db = get_db()
    posts = db.execute('SELECT id, name, description, price, sku FROM products ORDER BY id DESC').fetchall()
    return render_template('auth/products.html', posts=posts)

# Vulnerable search route (INTENTIONALLY UNSAFE for demonstration)
@bp.route('/products/search')
def products_search():
    q = request.args.get('q', '')
    # INTENTIONALLY UNSAFE: building SQL from raw input to demonstrate SQL injection vulnerability
    # Do NOT use this pattern in production. We'll include recommended fixes later.
    sql = f"SELECT id, name, description, price, sku FROM products WHERE name LIKE '%{q}%' LIMIT 100"
    db = get_db()
    rows = db.execute(sql).fetchall()
    return render_template('auth/product_search.html', q=q, rows=rows)

# register vulnerable
@bp.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None

        if not username:
            error = 'Username is required.'
        elif not password:
            error = 'Password is required.'

        if error is None:
            try:
                db.execute("INSERT INTO user (username, password) VALUES ('" + username + "', '" + password + "')",)
                db.commit()
            except db.IntegrityError:
                error = f"User {username} is already registered."
            else:
                return redirect(url_for("auth.login"))

        flash(error)

    return render_template("auth/register.html")

# register secure
@bp.route('/register-secure', methods=('GET', 'POST'))
def register_secure():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None

        if not username:
            error = 'Username is required.'
        elif not password:
            error = 'Password is required.'

        if error is None:
            try:
                db.execute("INSERT INTO usersecure (username, hash) VALUES (?, ?)", 
                           (username, generate_password_hash(password)),)
                db.commit()
            except db.IntegrityError:
                error = f"User {username} is already registered."
            else:
                return redirect(url_for("auth.login_secure"))

        flash(error)

    return render_template("auth/register_secure.html")

# login insecure
@bp.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None
        user = db.execute("SELECT id, username, password FROM user WHERE username = '" + username + "'").fetchone()
        if user is None:
            error = "Incorrect username"

        if error is None:
            session.clear()
            session['user_id'] = user['id']
            return redirect(url_for('auth.index', username=username))

        flash(error)

    return render_template('auth/login.html')

# login secure
@bp.route('/login-secure', methods=('GET', 'POST'))
def login_secure():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()

        error = None
        user = db.execute('SELECT * FROM usersecure WHERE username = ?', 
                          (username,)).fetchone()
        if user is None:
            error = "Incorrect username"
        elif not check_password_hash(user['hash'], password):
            error = 'Incorrect password.'

        if error is None:
            session.clear()
            session['user_id'] = user['id']
            return redirect(url_for('auth.index', username=username))

        flash(error)

    return render_template('auth/login_secure.html')

# session
@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * FROM user WHERE id = ?', (user_id,)
        ).fetchone()

# logout
@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('auth.login'))

# require authentication in other views
def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))

        return view(**kwargs)

    return wrapped_view