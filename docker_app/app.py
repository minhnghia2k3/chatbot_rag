import streamlit as st
import json
import boto3
from utils.auth import Auth
from utils.llm import Llm
from config_file import Config

# ID of Secrets Manager containing cognito parameters
secrets_manager_id = Config.SECRETS_MANAGER_ID

# ID of the AWS region in which Secrets Manager is deployed
region = Config.DEPLOYMENT_REGION

# Initialise CognitoAuthenticator
# authenticator = Auth.get_authenticator(secrets_manager_id, region)

# Authenticate user, and stop here if not logged in
# is_logged_in = authenticator.login()
# if not is_logged_in:
#     st.stop()


# def logout():
#     authenticator.logout()


# with st.sidebar:
#     st.text(f"Welcome,\n{authenticator.get_username()}")
#     st.button("Logout", "logout_btn", on_click=logout)

# Add title on the page
st.title("RAG Chatbot") #page title

# Ask user for input text
input_sent = st.chat_input("Chat with your bot here") #display a chat input box

# Create the large language model object
llm = Llm(Config.BEDROCK_REGION)

# When there is an input text to process
if input_sent:

    # Render user chat message
    with st.chat_message("user"):
        st.write(input_sent)

    # Invoke the Bedrock foundation model
    response = llm.invoke(input_sent) # TODO: write a backend handle model invoking

    # Transform response to json
    json_response = json.loads(response.get("body").read())

    # Format response and print it in the console
    pretty_json_output = json.dumps(json_response, indent=2)

    # Write response on Streamlit web interface
    with st.chat_message("assistant"):
        st.write("**Assistant** \n", json_response['completion'])
