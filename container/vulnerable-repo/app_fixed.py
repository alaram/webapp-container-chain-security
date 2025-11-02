import os
from flask import Flask, request

app = Flask(__name__)

# FIX 1: Retrieve secrets from environment variables
API_KEY = os.getenv("API_KEY", "default-safe-key")

@app.route('/shell')
def execute_shell_command():
    # FIX 2: Do not use dangerous shell execution functions (os.system)
    # If shell execution is required, use subprocess with 'shell=False' and sanitized arguments.
    # For this demo, we remove the dangerous functionality.
    
    user_input = request.args.get('command')
    
    if user_input:
        return f"Shell execution disabled for command: {user_input}"
    
    return "No dangerous shell function calls are used."

@app.route('/')
def index():
    return "Secure application is running."

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)