from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
import os
from dotenv import load_dotenv
import pandas as pd
import plotly
import json
from datetime import datetime

app = Flask(__name__)
CORS(app)

# Configuration
app.config['SECRET_KEY'] = 'your-secret-key-here'

# Load environment variables
load_dotenv()
MONGODB_URI = os.getenv('MONGODB_URI')

# MongoDB client and collections
client = MongoClient(MONGODB_URI)
db = client['nlp']
collection = db['cve']
kpi_collection = db['kpi_cache']

# Function to calculate and cache KPIs
def calculate_kpis():
    data = list(collection.find())
    df = pd.DataFrame(data)

    # Ensure necessary fields are in the correct format
    df['cvssScore'] = pd.to_numeric(df['cvssScore'], errors='coerce')
    df['publishedDate'] = pd.to_datetime(df['publishedDate'], errors='coerce')
    df = df.dropna(subset=['cvssScore', 'publishedDate'])

    # Calculate KPIs
    kpis = {
        'average_cvss': df['cvssScore'].mean(),
        'total_cves': len(df),
        'most_common_confidentiality_impact': df['confidentialityImpact'].mode()[0] if not df['confidentialityImpact'].mode().empty else None,
        'cves_last_year': len(df[df['publishedDate'].dt.year == pd.Timestamp.now().year - 1]),
        'last_calculated': datetime.now()  # Timestamp for reference
    }

    # Store KPIs in the MongoDB collection
    kpi_collection.update_one({}, {"$set": kpis}, upsert=True)
    return kpis

# Function to load KPIs from MongoDB or calculate if not available
def load_kpis():
    kpi_data = kpi_collection.find_one()
    if not kpi_data:
        kpi_data = calculate_kpis()
    else:
        kpi_data.pop('_id', None)  # Remove MongoDB-specific _id field
    return kpi_data


@app.route('/')
@app.route('/home')
def home():
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    # Load cached KPIs
    kpis = load_kpis()

    # Pagination and search setup
    page = request.args.get('page', default=1, type=int)
    query = request.args.get('query', default='', type=str)
    page_size = 10

    # Search functionality (simple text match on description)
    filter_query = {'id': {'$regex': query, '$options': 'i'}} if query else {}

    # Pagination and search query on MongoDB
    total_records = collection.count_documents(filter_query)
    data = list(collection.find(filter_query).skip((page - 1) * page_size).limit(page_size))

    # Pass KPIs, paginated data, and other details to the template
    return render_template('dashboard.html', kpis=kpis, data=data, page=page, page_size=page_size, total_records=total_records, query=query)

@app.route('/refresh-kpis')
def refresh_kpis():
    # Manual route to refresh KPIs
    kpis = calculate_kpis()
    return jsonify(kpis)


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
