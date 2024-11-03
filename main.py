from flask import Flask, render_template, redirect, url_for
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# Configuration
app.config['SECRET_KEY'] = 'your-secret-key-here'  # Change this to a secure secret key
app.config['TEMPLATES_AUTO_RELOAD'] = True  # Enable auto-reload of templates during development

# Routes
@app.route('/')
@app.route('/home')
def home():
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    # This route will be implemented later
    return "Dashboard page coming soon!"

@app.route('/cve')
def cve():
    # This route will be implemented later
    return "CVE page coming soon!"

# Error handlers
@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(error):
    return render_template('500.html'), 500

# Development server configuration
if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)