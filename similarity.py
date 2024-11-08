from transformers import BertTokenizer, AutoModel
import torch
import json
import warnings
warnings.filterwarnings('ignore')
import os
from dotenv import load_dotenv
from pinecone import Pinecone
from pymongo import MongoClient

load_dotenv()

MONGODB_URI = os.getenv('MONGODB_URI')
PINECONE_API_KEY = os.getenv('PINECONE_API_KEY')

pc = Pinecone(api_key=PINECONE_API_KEY)
index = pc.Index("cveindex")

client = MongoClient(MONGODB_URI)
db = client['nlp']
collection = db['data_for_vectordb']

class SimilaritySearch:
    def __init__(self):
        """Initialize the similarity search with model, embeddings, and data."""
        # Load the model
        model_name = "sentence-transformers/all-MiniLM-L6-v2"
        self.model = AutoModel.from_pretrained(model_name)
        self.tokenizer = BertTokenizer.from_pretrained('bert-base-uncased')


    def search(self, query, top_k=5):
        """
        Search for similar CVEs based on query.
        
        Args:
            query (str): Search query
            top_k (int): Number of results to return
            
        Returns:
            list: List of dictionaries containing search results
        """
        # Encode query
        query_encoded_inputs = self.tokenizer(query, padding=True, truncation=True, return_tensors='pt')
        query_token_ids = query_encoded_inputs['input_ids']
        query_attention_masks = query_encoded_inputs['attention_mask']
        outputs = self.model(input_ids=query_token_ids, attention_mask=query_attention_masks)
        query_embedding = outputs.last_hidden_state[:, 0, :]
        query_vector = query_embedding.tolist()[0]
        response = index.query( namespace="ns1", vector=query_vector, top_k=5)
        results = []
        for res in response['matches']:
            result = collection.find({"id":res['id']})
            data = list(result)
            description = "Not Available"
            if (len(data) > 0):
                description = data[0]['description']
            score = res['score']
            results.append({
                'cve_id' : res['id'],
                'description':description,
                'similarity_score':score
            })


        
        return results

# Initialize search engine once
search_engine = None

def get_search_engine():
    global search_engine
    if search_engine is None:
        search_engine = SimilaritySearch()
    return search_engine