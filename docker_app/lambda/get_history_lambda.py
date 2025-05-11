import boto3
import os
import json

dynamodb = boto3.resource("dynamodb")
TABLE_NAME = os.environ.get("TABLE_NAME")


def lambda_handler(event, context):
    session_id = event["session_id"]
    table = dynamodb.Table(TABLE_NAME)
    resp = table.query(
        KeyConditionExpression=boto3.dynamodb.conditions.Key("sessionId").eq(
            session_id
        ),
        Limit=10,
        ScanIndexForward=False,
    )
    history = [item["message"] for item in resp.get("Items", [])]
    return {"statusCode": 200, "body": json.dumps({"history": history})}
