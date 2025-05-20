import boto3
import json
import os
import time
from boto3.dynamodb.conditions import Key
from opensearchpy import OpenSearch, RequestsHttpConnection
from requests_aws4auth import AWS4Auth

dynamodb = boto3.resource("dynamodb")
bedrock = boto3.client("bedrock-runtime")

TABLE_NAME = os.environ.get("TABLE_NAME")
# OPENSEARCH_HOST = os.environ.get("OPENSEARCH_HOST")
# OPENSEARCH_INDEX = os.environ.get("OPENSEARCH_INDEX_NAME")
credentials = boto3.Session().get_credentials()
region = "us-east-1"  # set your region

# awsauth = AWS4Auth(
#     credentials.access_key,
#     credentials.secret_key,
#     region,
#     "aoss",  # OpenSearch Serverless
#     session_token=credentials.token,
# )


def get_conversation_history(session_id):
    table = dynamodb.Table(TABLE_NAME)
    resp = table.query(
        KeyConditionExpression=Key("sessionId").eq(session_id),
        Limit=10,
        ScanIndexForward=False,
    )
    return [item["message"] for item in resp.get("Items", [])]


def rephrase_query(user_query, history):
    messages = [
        {
            "role": "user",
            "content": f"Given the conversation history: {history}\nRephrase the user's question: {user_query}",
        }
    ]

    native_request = {
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 256,
        "temperature": 0.5,
        "messages": messages,
    }

    request = json.dumps(native_request)

    response = bedrock.invoke_model(
        modelId="anthropic.claude-3-haiku-20240307-v1:0",
        contentType="application/json",
        accept="application/json",
        body=request,
    )
    result = json.loads(response["body"].read())
    return result["content"][0]["text"]


def get_embedding(text):
    response = bedrock.invoke_model(
        modelId="amazon.titan-embed-text-v1",
        contentType="application/json",
        accept="application/json",
        body=json.dumps({"inputText": text}),
    )
    result = json.loads(response["body"].read())
    embedding = result["embedding"]
    return embedding


# def query_opensearch(embedding):
#     client = OpenSearch(
#         hosts=[{"host": OPENSEARCH_HOST, "port": 443}],
#         http_auth=awsauth,
#         use_ssl=True,
#         verify_certs=True,
#         connection_class=RequestsHttpConnection,
#     )
#     query = {"size": 5, "query": {"knn": {"embedding": {"vector": embedding, "k": 5}}}}
#     resp = client.search(index=OPENSEARCH_INDEX, body=query)
#     return [hit["_source"]["text"] for hit in resp["hits"]["hits"]]


def build_augmented_prompt(history, context_chunks, user_query):
    context = "\n".join(context_chunks)
    return (
        f"Conversation history:\n{history}\n\n"
        f"Context:\n{context}\n\n"
        f"User question:\n{user_query}\n\n"
        "Instructions: Answer the question using the context and history. Be concise and accurate."
    )


def invoke_llm(prompt):
    native_request = {
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 256,
        "temperature": 0.5,
        "messages": [
            {
                "role": "user",
                "content": [{"type": "text", "text": prompt}],
            }
        ],
    }

    request = json.dumps(native_request)

    response = bedrock.invoke_model(
        modelId="anthropic.claude-3-haiku-20240307-v1:0",
        contentType="application/json",
        accept="application/json",
        body=request,
    )
    result = json.loads(response["body"].read())
    return result["content"][0]["text"]


def store_conversation_turn(session_id, user_query, llm_response):
    table = dynamodb.Table(TABLE_NAME)
    table.put_item(
        Item={
            "sessionId": session_id,
            "timestamp": int(time.time()),
            "message": user_query,
            "response": llm_response,
        }
    )


def lambda_handler(event, context):
    session_id = event["session_id"]
    user_query = event["user_query"]

    history = get_conversation_history(session_id)
    rephrased_query = rephrase_query(user_query, history)
    embedding = get_embedding(rephrased_query)
    # context_chunks = query_opensearch(embedding)
    context_chunks = ""
    augmented_prompt = build_augmented_prompt(history, context_chunks, user_query)
    llm_response = invoke_llm(augmented_prompt)
    store_conversation_turn(session_id, user_query, llm_response)
    return {"statusCode": 200, "body": json.dumps({"response": llm_response})}
