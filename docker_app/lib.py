import boto3
import json
import os
from opensearchpy import OpenSearch, RequestsHttpConnection

# Initialize AWS clients
dynamodb = boto3.resource("dynamodb")
bedrock = boto3.client("bedrock-runtime")

# Environment variables for resource names
TABLE_NAME = os.environ.get("TABLE_NAME")
OPENSEARCH_HOST = os.environ.get("OPENSEARCH_HOST")
OPENSEARCH_INDEX = os.environ.get("OPENSEARCH_INDEX")


# Helper: Retrieve conversation history from DynamoDB
def get_conversation_history(session_id):
    table = dynamodb.Table(TABLE_NAME)
    resp = table.query(
        KeyConditionExpression=boto3.dynamodb.conditions.Key("sessionId").eq(
            session_id
        ),
        Limit=10,
        ScanIndexForward=False,
    )
    return [item["message"] for item in resp.get("Items", [])]


# Helper: Rephrase user query (using Bedrock LLM)
def rephrase_query(user_query, history):
    prompt = f"Given the conversation history: {history}\nRephrase the user's question: {user_query}"
    response = bedrock.invoke_model(
        modelId="anthropic.claude-v2",  # Example model
        contentType="application/json",
        accept="application/json",
        body=json.dumps({"prompt": prompt, "max_tokens": 64}),
    )
    result = json.loads(response["body"].read())
    return result["completion"]


# Helper: Get embedding from Amazon Titan
def get_embedding(text):
    response = bedrock.invoke_model(
        modelId="amazon.titan-embed-text-v1",  # Titan Embeddings model
        contentType="application/json",
        accept="application/json",
        body=json.dumps({"inputText": text}),
    )
    result = json.loads(response["body"].read())
    embedding = result["embedding"]
    return embedding


# Helper: Query OpenSearch for similar documents
def query_opensearch(embedding):
    client = OpenSearch(
        hosts=[{"host": OPENSEARCH_HOST, "port": 443}],
        http_auth=(os.environ["OS_USER"], os.environ["OS_PASS"]),
        use_ssl=True,
        verify_certs=True,
        connection_class=RequestsHttpConnection,
    )
    query = {"size": 5, "query": {"knn": {"embedding": {"vector": embedding, "k": 5}}}}
    resp = client.search(index=OPENSEARCH_INDEX, body=query)
    return [hit["_source"]["text"] for hit in resp["hits"]["hits"]]


# Helper: Augment prompt for LLM
def build_augmented_prompt(history, context_chunks, user_query):
    context = "\n".join(context_chunks)
    prompt = (
        f"Conversation history:\n{history}\n\n"
        f"Context:\n{context}\n\n"
        f"User question:\n{user_query}\n\n"
        "Instructions: Answer the question using the context and history. Be concise and accurate."
    )
    return prompt


# Helper: Invoke LLM (Bedrock)
def invoke_llm(prompt):
    response = bedrock.invoke_model(
        modelId="anthropic.claude-v2",
        contentType="application/json",
        accept="application/json",
        body=json.dumps({"prompt": prompt, "max_tokens": 256}),
    )
    result = json.loads(response["body"].read())
    return result["completion"]


# Helper: Store conversation turn in DynamoDB
def store_conversation_turn(session_id, user_query, llm_response):
    table = dynamodb.Table(TABLE_NAME)
    table.put_item(
        Item={
            "session_id": session_id,
            "timestamp": int(
                boto3.client("sts").get_caller_identity()["ResponseMetadata"][
                    "HTTPHeaders"
                ]["date"]
            ),
            "message": user_query,
            "response": llm_response,
        }
    )


# Lambda handler
def lambda_handler(event, context):
    session_id = event["session_id"]
    user_query = event["user_query"]

    # (a) Retrieve conversation history
    history = get_conversation_history(session_id)

    # (b) Rephrase user query
    rephrased_query = rephrase_query(user_query, history)

    # (c) Get embedding
    embedding = get_embedding(rephrased_query)

    # (d) Query OpenSearch
    context_chunks = query_opensearch(embedding)

    # (e) Augment prompt
    augmented_prompt = build_augmented_prompt(history, context_chunks, user_query)

    # (f) Invoke LLM
    llm_response = invoke_llm(augmented_prompt)

    # (h) Store conversation turn
    store_conversation_turn(session_id, user_query, llm_response)

    # (i) Return response
    return {"statusCode": 200, "body": json.dumps({"response": llm_response})}
