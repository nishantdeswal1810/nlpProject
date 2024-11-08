from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
import os
from dotenv import load_dotenv
import pandas as pd
import plotly
import json
from datetime import datetime
from langchain_groq import ChatGroq
import re
import markdown2
from similarity import *

app = Flask(__name__)
CORS(app)

# Configuration
app.config['SECRET_KEY'] = 'your-secret-key-here'

# Load environment variables
load_dotenv()
MONGODB_URI = os.getenv('MONGODB_URI')
GROQ_API_KEY= os.getenv('GROQ_API_KEY')

# MongoDB client and collections
client = MongoClient(MONGODB_URI)
db = client['nlp']
collection = db['cve']
cve_collection=db['cve']
kpi_collection = db['kpi_cache']

# Defining LLM
llm = ChatGroq(
    model="llama-3.1-8b-instant",
    temperature=0,
    max_tokens=None,
    timeout=None,
    max_retries=2,
)

def summarize_cve_id(cve_id):
    print(f"Received CVE ID: {cve_id}")
    query = {"id": cve_id}
    result = cve_collection.find(query)
    result_data = list(result)
    if result_data:
        processed_data = {
            key: (value if key != '_id' else None) for key, value in result_data[0].items()
            if key != '_id'
        }
        print(f"Processed Data: {processed_data}")

        refs = processed_data['references']
        corrected_refs = []
        for ref in refs:
            url_pattern = r'([a-zA-Z]+://)?[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/[^\s\'"]*)?'
            url_match = re.search(url_pattern, ref)
            
            if url_match:
                corrected_refs.append(url_match.group(0))
        processed_data['references'] = corrected_refs
        
        prompt = str(processed_data)
        messages = [
            ("system", """You are an assistant who reads the data related to CVE ID, provides the detail of the description of CVE_ID and some other points like impact, exploitability and you need to find a patch if there is an update or patch is there"""),
            ("human", prompt),
        ]

        try:
            ai_msg = llm.invoke(messages)
            print(f"LLM Response: {ai_msg.content}")
            processed_data['LLM_Response'] = markdown2.markdown(ai_msg.content)
            return processed_data
    
        except Exception as e:
            print(f"Error with LLM invocation: {e}")
            return jsonify({"error": "Failed to retrieve LLM response"}), 500
  
    else:
        print("No data found for the given CVE ID")  # Debug: No data found
        return None

@app.route('/cve', methods=['GET', 'POST'])
def cve():
    if request.method == 'POST':
        cve_id = request.form['cve_id']
        cve_data = summarize_cve_id(cve_id)
        if cve_data:
            return render_template('cve.html', cve_data=cve_data)
        else:
            return render_template('404.html'), 404
    return render_template('cve.html')

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

@app.route('/similar-search')
def similar_search():
    return render_template('search.html')

@app.route('/api/search', methods=['POST'])
def similarity_search():
    try:
        data = request.get_json()
        if not data or 'query' not in data:
            return jsonify({'error': 'No query provided'}), 400
            
        query = data['query']
        top_k = data.get('top_k', 5)
        
        # Get search engine instance
        search_engine = get_search_engine()
        
        # Perform search
        results = search_engine.search(query, top_k)
        
        return jsonify({'results': results})
        
    except Exception as e:
        print(f"Search error: {str(e)}")  # For debugging
        return jsonify({'error': 'Search failed. Please try again.'}), 500

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


# @app.route('/cve')
# def cve():
#     # This route will be implemented later
#     return "CVE page coming soon!"

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
