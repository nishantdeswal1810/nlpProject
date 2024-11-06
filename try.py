from pymongo import MongoClient
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()
MONGODB_URI = os.getenv('MONGODB_URI')

# Verify if MONGODB_URI is loaded
if not MONGODB_URI:
    print("Error: MONGODB_URI not found in environment. Check your .env file.")
else:
    print("MongoDB URI:", MONGODB_URI)

# MongoDB client
client = MongoClient(MONGODB_URI)

# List all databases to confirm connection
print("Databases available:")
databases = client.list_database_names()
print(databases)

# Check if 'nlp' database is in the list
if 'nlp' in databases:
    print("'nlp' database found.")
    db = client['nlp']  # Connect to the 'nlp' database
else:
    print("Error: 'nlp' database not found.")
    exit()

# List collections in 'nlp' database
collections = db.list_collection_names()
print("Collections in 'nlp' database:", collections)

# Check if 'cve' collection is in the list
if 'cve' in collections:
    print("'cve' collection found.")
    collection = db['cve']  # Define the collection
else:
    print("Error: 'cve' collection not found.")
    exit()

# Attempt to retrieve and print the first 2 documents from 'cve' collection
try:
    data = list(collection.find().limit(2))
    if data:
        print("Successfully retrieved the first 2 documents:")
        for i, doc in enumerate(data, start=1):
            print(f"Document {i}: {doc}")
    else:
        print("No documents found in the 'cve' collection.")
except Exception as e:
    print("An error occurred while retrieving documents:", e)
