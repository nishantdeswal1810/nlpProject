import re
from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
import os
from dotenv import load_dotenv
import json
from datetime import datetime
from langchain_groq import ChatGroq

app = Flask(__name__)
CORS(app)

# Load environment variables
load_dotenv()
MONGODB_URI = os.getenv('MONGODB_URI')
GROQ_API_KEY = os.getenv('GROQ_API_KEY')

# MongoDB client and collections
client = MongoClient(MONGODB_URI)
db = client['nlp']
collection = db['cve']

# Defining LLM
llm = ChatGroq(
    model="llama-3.1-8b-instant",
    temperature=0,
    max_tokens=None,
    timeout=None,
    max_retries=2,
)

def summarize_cve_id(cve_id):
    query = {"id": cve_id}
    result = collection.find(query)
    result_data = list(result)
    if result_data[0]:
        processed_data = {
                    key: (value if key != '_id' else None) for key, value in result_data[0].items()
                    if key != '_id'
                }
        refs = processed_data['references']
        corrected_refs = []
        for ref in refs:
            url_pattern = r'([a-zA-Z]+://)?[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/[^\s\'"]*)?'
            url_match = re.search(url_pattern, ref)
            corrected_refs.append(url_match.group(0))
        processed_data['references'] = corrected_refs
        prompt = str(processed_data)
        messages = [
             ("system","""You are an assistant who reads the data related to CVE ID, provides the detail of the description of CVE_ID and some other points like impact, exploitability and you need to find a patch if there is an update or patch is there""",),("human", prompt),
        ]
        ai_msg = llm.invoke(messages)
        processed_data['LLM_Response'] = ai_msg.content
        return jsonify(processed_data)
    else:
        return None

@app.route('/')
def hello():
    return "hello!"

@app.route('/submit', methods=['POST'])
def submit_data():
    data = request.get_json()  # Assuming JSON data is sent
    if not data:
        return jsonify({"error": "No data provided"}), 400
    
    cve_id = data.get('cve_id')
    response = summarize_cve_id(cve_id)
    return response, 200  # Return a JSON response with a 200 OK status

# Run the app
if __name__ == '__main__':
    app.run(debug=True)