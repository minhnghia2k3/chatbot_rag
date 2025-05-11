import streamlit as st
import boto3
import os
import json
from utils.auth import Auth
from utils.llm import Llm
from config_file import Config

lambda_client = boto3.client("lambda", region_name=Config.DEPLOYMENT_REGION)
LAMBDA_FUNCTION_NAME = "RAGLambdaFunction"
HISTORY_FUNCTION_NAME = "GetHistoryLambda"

# S3 client for uploads
s3_client = boto3.client("s3", region_name=Config.DEPLOYMENT_REGION)
PDF_BUCKET = os.environ["PDF_BUCKET"]

# ID of Secrets Manager containing cognito parameters
secrets_manager_id = Config.SECRETS_MANAGER_ID
region = Config.DEPLOYMENT_REGION

# Initialise CognitoAuthenticator
authenticator = Auth.get_authenticator(secrets_manager_id, region)

# Authenticate user, and stop here if not logged in
is_logged_in = authenticator.login()
if not is_logged_in:
    st.stop()


def logout():
    authenticator.logout()


with st.sidebar:
    st.text(f"Welcome,\n{authenticator.get_username()}")
    st.button("Logout", "logout_btn", on_click=logout)

tab1, tab2 = st.tabs(["Chat", "Upload PDF"])

# Place chat input at the top level
input_sent = st.chat_input("Chat with your bot here")

with tab1:
    st.title("RAG Chatbot")
    llm = Llm(Config.BEDROCK_REGION)
    session_id = authenticator.get_username()

    history_payload = {"session_id": session_id}
    history_response = lambda_client.invoke(
        FunctionName=HISTORY_FUNCTION_NAME,
        InvocationType="RequestResponse",
        Payload=json.dumps(history_payload),
    )
    history_data = json.loads(history_response["Payload"].read())

    if "body" in history_data:
        history = json.loads(history_data["body"]).get("history", [])
        for msg in reversed(history):
            with st.chat_message("user"):
                st.write(msg)

    if input_sent:
        with st.chat_message("user"):
            st.write(input_sent)

        payload = {
            "session_id": session_id,
            "user_query": input_sent,
        }

        lambda_response = lambda_client.invoke(
            FunctionName=LAMBDA_FUNCTION_NAME,
            InvocationType="RequestResponse",
            Payload=json.dumps(payload),
        )

        response_payload = json.loads(lambda_response["Payload"].read())
        st.write("Lambda raw response:", response_payload)
        if "body" in response_payload:
            try:
                body = json.loads(response_payload["body"])
                llm_response = body.get("response", "")
            except Exception as e:
                st.error(f"Error parsing Lambda response body: {e}")
                st.write(response_payload)
                llm_response = ""
        else:
            st.error("Unexpected Lambda response format (no 'body' key)")
            st.write(response_payload)
            llm_response = ""

        with st.chat_message("assistant"):
            st.write("**Assistant** \n", llm_response)

with tab2:
    st.header("Upload Knowledge Base PDF")
    uploaded_file = st.file_uploader("Choose a PDF file", type=["pdf"])
    if uploaded_file is not None:
        temp_path = f"/tmp/{uploaded_file.name}"
        with open(temp_path, "wb") as f:
            f.write(uploaded_file.read())
        s3_client.upload_file(temp_path, PDF_BUCKET, uploaded_file.name)
        st.success(f"Uploaded {uploaded_file.name} to knowledge base!")
