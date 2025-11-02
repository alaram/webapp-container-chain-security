import re
import os
import functools
import subprocess

from flask import Blueprint, flash, g, redirect, render_template, request, session, url_for, Flask, make_response
from werkzeug.security import check_password_hash, generate_password_hash
from flaskr.db import get_db

bp = Blueprint('auth', __name__, url_prefix='/auth')
app = Flask(__name__)

# Mock "Database" (an in-memory list to store raw comments)
# In a real app, this would be a SQL database or similar.
comments_db = []

# --- 1. Comment Submission Route (The Injection Point) ---
# perform the attack with <script>alert('Stored XSS Worked!')</script>
@bp.route('/submit_comment', methods=['POST'])
def submit_comment():
    # ⚠️ VULNERABILITY: Input is taken and stored RAW, with NO sanitization.
    comment_content = request.form.get('content', 'Empty Comment')
    
    # Store the raw, unsanitized input into the mock DB
    comments_db.append({'content': comment_content})
    
    # Redirect to the view page
    return redirect(url_for('auth.view_comments'))

# --- 2. Comment retrieval Route ---
@bp.route('/comments', methods=['GET'])
def view_comments():
    comments_html = ""

    for comment in comments_db:
        # ⚠️ VULNERABILITY: Constructing HTML with raw stored data.
        # This simulates using a function that bypasses escaping (like Jinja's |safe).
        comments_html += f"<div class='comment'>Author: Attacker<br>Comment: {comment['content']}</div><hr>"
    
    # Construct the raw HTML response page
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head><title>Stored XSS Test</title></head>
    <body>
        <h1>Vulnerable Comments Section</h1>
        
        <form action="{url_for('auth.submit_comment')}" method="POST">
            <textarea name="content" rows="4" cols="50" placeholder="Enter XSS payload here..."></textarea><br>
            <input type="submit" value="Post Comment">
        </form>
        
        <h2>All Comments:</h2>
        {comments_html}
        
    </body>
    </html>
    """
    response = make_response(html_content)
    response.headers['Content-Type'] = 'text/html'
    return response

#OS command injection via a diagnostics shell command
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

# Products search route with security vulnerabillty 
# XSS (INTENTIONALLY UNSAFE for demonstration)
@bp.route('/products/vulnerable/search', methods=['GET'])
def products_search_vulnerable():
    #q = request.args.get('q', '')
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head><title>Raw HTML Search</title></head>
    <body>
        <h2>Raw HTML Form</h2>
        <form action="" method="get">
            <a href="javascript:alert('unsafe');">click here</a>
            <p/>
            <input name="q" value="">
            <input type="submit" value="Search" onclick=alert('XSS')>
        </form>
    </body>
    </html>
    """

    # Create the response object
    response = make_response(html_content)
    # Set the Content-Type header
    response.headers['Content-Type'] = 'text/html'
    return response

# Safe search route for defend against 
# SQL Injection search textbox
@bp.route('/products/injection/search', methods=['GET'])
def products_injection_search():
    
    q = request.args.get('q', '')

    # INTENTIONALLY UNSAFE: building SQL from raw input to demonstrate 
    # SQL injection vulnerability. Do NOT use this pattern in production.
    sql = f"SELECT id, name, description, price, sku FROM products WHERE name LIKE '%{q}%' LIMIT 100"
    rows = get_db().execute(sql).fetchall()
    return render_template('auth/product_injection_search.html', q=q, rows=rows)

# Safe search route for defend against 
# SQL Injection
@bp.route('/products/secure/search', methods=['GET'])
def products_secure_search():

    # 1. Prepare the search term for LIKE
    # Add the wildcards (%) outside the SQL query string
    q = request.args.get('q', '')

    # 2. Define the SQL query with a placeholder (e.g., ?)
    sql = "SELECT id, name, description, price, sku FROM products WHERE name LIKE ? LIMIT 100"

    # 3. Execute the query using the placeholder and passing the data separately
    # The database driver will safely escape the search_term.
    # The data is passed as a tuple
    rows = get_db().execute(sql, (f"%{q}%",)).fetchall()
    return render_template('auth/product_secure_search.html', q=q, rows=rows)

# register vulnerable
#@bp.route('/register', methods=('GET', 'POST'))
#def register():
#    if request.method == 'POST':
#        username = request.form['username']
#        password = request.form['password']
#        db = get_db()
#        error = None
#
#        if not username:
#            error = 'Username is required.'
#        elif not password:
#            error = 'Password is required.'
#
#        if error is None:
#            try:
#                db.execute("INSERT INTO user (username, password) VALUES ('" + username + "', '" + password + "')",)
#                db.commit()
#            except db.IntegrityError:
#                error = f"User {username} is already registered."
#            else:
#                return redirect(url_for("auth.login"))
#
#        flash(error)
#
#    return render_template("auth/register.html")

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

# This method perform the 
# login insecure, by requesting username/password
# and using the username included in the error message 
# and will be displayed back to the user without being encoded later.
# This method also creates a raw html page with no security/validation
# whatsoever
@bp.route('/login', methods=('GET', 'POST'))
def login():
    error_message = ""
    
    if request.method == 'POST':
        # Get user input from the form
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        # Simulate a failed login and construct the error message
        # ⚠️ VULNERABILITY: The username is included in the error message 
        # and will be displayed back to the user without being encoded later.
        error_message = f"Login failed for user: {username}. Please try again."
        
    # Construct the raw HTML page, inserting the unescaped error message
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Vulnerable Login Test</title>
        <style>
            .error {{ color: red; font-weight: bold; }}
            form {{ padding: 20px; border: 1px solid #ccc; width: 300px; }}
        </style>
    </head>
    <body>
        <h1>Vulnerable Login Page</h1>
        
        <p class="error">{error_message}</p>
        
        <form method="POST">
            <label for="username">Username:</label><br>
            <input type="text" id="username" name="username"><br><br>
            
            <label for="password">Password:</label><br>
            <input type="password" id="password" name="password"><br><br>
            
            <input type="submit" value="Login">
        </form>
    </body>
    </html>
    """
    
    response = make_response(html_content)
    response.headers['Content-Type'] = 'text/html'
    return response

# This method perform the 
# login secure, by requesting username/password
# and using * HTML escaping in templates ({{ user|e }})
# and parameterized SQL queries (? in SQLite or %s in psycopg2)
# with validation of Users hash against in the DB.
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

# This methood holds the session
# for the authenticated user
@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute('SELECT * FROM user WHERE id = ?', (user_id,)).fetchone()

# This method will call the logout and 
# clear the session
@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('auth.login_secure'))

# This method performs the authentication in other views
def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))

        return view(**kwargs)

    return wrapped_view