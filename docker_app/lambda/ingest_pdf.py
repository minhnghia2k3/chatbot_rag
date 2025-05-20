import json
import os
import boto3
from opensearchpy import OpenSearch, RequestsHttpConnection
import PyPDF2


def extract_text_from_pdf(pdf_path):
    text = ""
    with open(pdf_path, "rb") as file:
        reader = PyPDF2.PdfReader(file)
        for page in reader.pages:
            page_text = page.extract_text()
            if page_text:
                text += page_text + "\n"
    return text


def chunk_text(text, chunk_size=500):
    words = text.split()
    return [
        " ".join(words[i : i + chunk_size]) for i in range(0, len(words), chunk_size)
    ]


def get_embedding(text, bedrock_client):
    response = bedrock_client.invoke_model(
        modelId="amazon.titan-embed-text-v1",
        contentType="application/json",
        accept="application/json",
        body=json.dumps({"inputText": text}),
    )
    result = json.loads(response["body"].read())
    return result["embedding"]


def index_chunk(opensearch_client, index_name, chunk, embedding, chunk_id, source):
    doc = {
        "text": chunk,
        "embedding": embedding,
        "metadata": {"source": source, "chunk_id": chunk_id},
    }
    opensearch_client.index(index=index_name, id=chunk_id, body=doc)


def lambda_handler(event, context):
    # # Get environment variables
    # # OPENSEARCH_HOST = os.environ["OPENSEARCH_HOST"]
    # # OPENSEARCH_INDEX = os.environ["OPENSEARCH_INDEX"]
    # BEDROCK_REGION = os.environ["BEDROCK_REGION"]
    # BUCKET_NAME = os.environ["BUCKET_NAME"]
    # CHUNK_SIZE = 500

    # # Parse S3 event
    # s3_info = event["Records"][0]["s3"]
    # bucket = s3_info["bucket"]["name"]
    # key = s3_info["object"]["key"]

    # # Download PDF to /tmp/
    # s3 = boto3.client("s3")
    # local_path = f"/tmp/{os.path.basename(key)}"
    # s3.download_file(bucket, key, local_path)

    # # Extract text from PDF
    # text = extract_text_from_pdf(local_path)
    # chunks = chunk_text(text, CHUNK_SIZE)

    # # Initialize Bedrock and OpenSearch clients
    # bedrock = boto3.client("bedrock-runtime", region_name=BEDROCK_REGION)
    # opensearch = OpenSearch(
    #     hosts=[{"host": OPENSEARCH_HOST, "port": 443}],
    #     use_ssl=True,
    #     verify_certs=True,
    #     connection_class=RequestsHttpConnection,
    # )

    # # Ingest each chunk
    # for i, chunk in enumerate(chunks):
    #     embedding = get_embedding(chunk, bedrock)
    #     index_chunk(
    #         opensearch,
    #         OPENSEARCH_INDEX,
    #         chunk,
    #         embedding,
    #         f"{os.path.basename(key)}_chunk_{i}",
    #         key,
    #     )

    # return {"statusCode": 200, "body": f"Ingested {len(chunks)} chunks from {key}"}
    return {"statusCode": 200, "body": f"Implementation pending"}
