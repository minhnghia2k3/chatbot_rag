import streamlit as st
import boto3
import json
import os
from utils.auth import Auth
from utils.llm import Llm
from config_file import Config

# Get environment variables with fallbacks
lambda_client = boto3.client("lambda", region_name=Config.DEPLOYMENT_REGION)
prefix = Config.STACK_NAME
LAMBDA_FUNCTION_NAME = os.environ.get(
    "LAMBDA_FUNCTION_NAME", f"{prefix}RAGLambdaFunction"
)
HISTORY_FUNCTION_NAME = os.environ.get(
    "HISTORY_FUNCTION_NAME", f"{prefix}GetHistoryLambda"
)

# S3 client for uploads
s3_client = boto3.client("s3", region_name=Config.DEPLOYMENT_REGION)
PDF_BUCKET = os.environ.get(
    "PDF_BUCKET", "streamlit-streamlitknowledgebasebucketa9338ef5-feoy2u2ha782"
)

# ID of Secrets Manager containing cognito parameters
secrets_manager_id = Config.SECRETS_MANAGER_ID
region = Config.DEPLOYMENT_REGION

# Initialise CognitoAuthenticator
authenticator = Auth.get_authenticator(secrets_manager_id, region)

# Authenticate user, and stop here if not logged in
is_logged_in = authenticator.login()
if not is_logged_in:
    st.stop()

session_id = authenticator.get_username()


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

    try:
        history_payload = {"session_id": session_id}
        history_response = lambda_client.invoke(
            FunctionName=HISTORY_FUNCTION_NAME,
            InvocationType="RequestResponse",
            Payload=json.dumps(history_payload),
        )
        history_data = json.loads(history_response["Payload"].read())

        if "body" in history_data:
            db_history = json.loads(history_data["body"]).get("history", [])

            if "chat_history" not in st.session_state:
                st.session_state.chat_history = db_history
            else:

                existing_msgs = {
                    item.get("timestamp", ""): True
                    for item in st.session_state.chat_history
                }

                for item in db_history:
                    timestamp = item.get("timestamp", "")
                    if timestamp not in existing_msgs:
                        st.session_state.chat_history.append(item)

            if not st.session_state.chat_history:
                st.info("No conversation history yet. Ask a question to get started!")
            else:
                sorted_history = sorted(
                    st.session_state.chat_history,
                    key=lambda x: x.get("timestamp", 0),
                    reverse=True,
                )

                for item in sorted_history:
                    with st.chat_message("user"):
                        st.write(item["message"])

                    with st.chat_message("assistant"):
                        st.write(item["response"])
    except Exception as e:
        st.error(f"Error retrieving conversation history: {str(e)}")
    st.title("RAG Chatbot")
    llm = Llm(Config.BEDROCK_REGION)

    try:
        history_payload = {"session_id": session_id}
        history_response = lambda_client.invoke(
            FunctionName=HISTORY_FUNCTION_NAME,
            InvocationType="RequestResponse",
            Payload=json.dumps(history_payload),
        )
        history_data = json.loads(history_response["Payload"].read())

        if "body" in history_data:
            history = json.loads(history_data["body"]).get("history", [])

            if not history:
                st.info("No conversation history yet. Ask a question to get started!")

            for item in reversed(history):
                # Display user message
                with st.chat_message("user"):
                    st.write(item["message"])

                # Display assistant response
                with st.chat_message("assistant"):
                    st.write(item["response"])
    except Exception as e:
        st.error(f"Error retrieving conversation history: {str(e)}")

    if input_sent:
        with st.chat_message("user"):
            st.write(input_sent)

        try:
            payload = {
                "session_id": session_id,
                "user_query": input_sent,
            }

            with st.spinner("Thinking..."):
                lambda_response = lambda_client.invoke(
                    FunctionName=LAMBDA_FUNCTION_NAME,
                    InvocationType="RequestResponse",
                    Payload=json.dumps(payload),
                )

                response_payload = json.loads(lambda_response["Payload"].read())
                if "body" in response_payload:
                    body = json.loads(response_payload["body"])
                    llm_response = body.get("response", "")
                else:
                    st.error("Unexpected Lambda response format (no 'body' key)")
                    llm_response = "Sorry, I couldn't process your request."

            with st.chat_message("assistant"):
                st.write(llm_response)

        except Exception as e:
            st.error(f"Error processing your request: {str(e)}")

with tab2:
    st.header("Upload Knowledge Base PDF")
    uploaded_file = st.file_uploader("Choose a PDF file", type=["pdf"])
    if uploaded_file is not None:
        try:
            with st.spinner("Uploading file..."):
                temp_path = f"/tmp/{uploaded_file.name}"
                with open(temp_path, "wb") as f:
                    f.write(uploaded_file.read())
                s3_client.upload_file(temp_path, PDF_BUCKET, uploaded_file.name)
                st.success(f"Uploaded {uploaded_file.name} to knowledge base!")
        except Exception as e:
            st.error(f"Error uploading file: {str(e)}")
