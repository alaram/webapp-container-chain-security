import os
from flask import Flask, request

app = Flask(__name__)

# VULNERABILITY 1: Hardcoded secret that Bandit will detect after scanning
API_KEY = "sk-live-1234567890abcdef" 

@app.route('/shell')
def execute_shell_command():
    # VULNERABILITY 2: Use of os.system/subprocess without proper input sanitization that Bandit will detect after scanning
    user_input = request.args.get('command', 'echo No command provided')
    
    # This is a dangerous function call
    os.system(f"echo Running command: {user_input}") 
    
    return f"Executed: {user_input}"

@app.route('/')
def index():
    return "Vulnerable application is running."

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)
