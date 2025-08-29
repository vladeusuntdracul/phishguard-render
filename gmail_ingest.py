import os, base64
from typing import List, Dict
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

def gmail_authenticate(creds_path="credentials.json", token_path="token.json"):
    creds = None
    if os.path.exists(token_path):
        creds = Credentials.from_authorized_user_file(token_path, SCOPES)
    if not creds or not creds.valid:
        flow = InstalledAppFlow.from_client_secrets_file(creds_path, SCOPES)
        creds = flow.run_local_server(port=0)
        with open(token_path, "w") as token:
            token.write(creds.to_json())
    return creds

def list_message_ids(service, query="newer_than:7d", max_results=20) -> List[str]:
    resp = service.users().messages().list(userId="me", q=query, maxResults=max_results).execute()
    return [m["id"] for m in resp.get("messages", [])]

def get_message_raw(service, msg_id: str) -> str:
    msg = service.users().messages().get(userId="me", id=msg_id, format="raw").execute()
    raw = msg["raw"]
    return base64.urlsafe_b64decode(raw).decode("utf-8", errors="ignore")