#continuous listening
from fastapi import FastAPI
from pymongo import MongoClient
from deepseek import DeepSeek
from knowledge_retrieval import knowledge_graph
from deepseek2 import DeepSeekD


app = FastAPI()

@app.get("/{item_id1}")
async def root(item_id1: str):
    a = []
    deepseek = DeepSeek()
    knowledge_graph_instance = knowledge_graph()  # Instantiate correctly
    responses = knowledge_graph_instance.CVE_extraction(item_id1)  # Extract CVE responses
    
    for response in responses:
        if response != 'None':
            question = f"Explain the vulnerability whose CVE-ID is {response}"
            explanation = deepseek.query(question)  # Get the explanation from DeepSeek
            a.append(explanation) 
    
    message = a  # Corrected assignment

    dD = DeepSeekD()
    question = f"Summarize the JSON: {message}"
    xx = dD.query(str(message))  # Ensure proper string conversion for query

    return {"message": xx}

@app.get("/items/{item_id}")
def read_item(item_id: int):
    return {"item_id": item_id}