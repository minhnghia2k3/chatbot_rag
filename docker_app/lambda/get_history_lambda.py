import boto3
import os
import json
from boto3.dynamodb.conditions import Key

dynamodb = boto3.resource("dynamodb")
TABLE_NAME = os.environ.get("TABLE_NAME")


def lambda_handler(event, context):
    session_id = event["session_id"]
    table = dynamodb.Table(TABLE_NAME)

    resp = table.query(
        KeyConditionExpression=Key("sessionId").eq(session_id),
        Limit=10,
        ScanIndexForward=False,
    )

    # Return complete items with both message and response
    history = [
        {
            "message": item["message"],
            "response": item["response"],
            "timestamp": item["timestamp"],
        }
        for item in resp.get("Items", [])
    ]
    # log history
    print(f"History for session {session_id}: {history}")
    return {
        "statusCode": 200,
        "body": json.dumps(
            {
                "history": [
                    {
                        "message": "user msg",
                        "response": "assistant response",
                        "timestamp": 123456789,
                    }
                ]
            }
        ),
    }
