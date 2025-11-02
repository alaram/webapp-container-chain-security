# app.py
import os
from flask import Flask

app = Flask(__name__)

# Read the environment variable once, when the application starts
SECRET_VALUE = os.getenv('RUNTIME_SECRET', 'SECRET NOT FOUND')

# 💡 NEW: Log the secret immediately upon application loading
# This ensures it appears in the Docker logs the moment 'flask run' executes.
print(f"--- APPLICATION STARTED ---")
print(f"--- INJECTED SECRET CHECK: {SECRET_VALUE} ---")
print(f"---------------------------")

@app.route('/')
def index():
    return f"Secret logged. Check docker logs for: {SECRET_VALUE}"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)