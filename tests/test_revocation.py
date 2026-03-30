
import requests
import json
import uuid
import time

BASE_URL = "http://127.0.0.1:8000"

def test_revocation_flow():
    # 1. Login to get token
    # We already have a testuser from the previous task, let's use it or create a new one
    # For simplicity, let's just use the register/login flow if needed, 
    # but we can also assume the credentials if we know them.
    # From previous step: username="testuser2", password="testpassword123"
    
    login_data = {"username": "testuser2", "password": "testpassword123"}
    resp = requests.post(f"{BASE_URL}/api/auth/login", data=login_data)
    if resp.status_code != 200:
        # Maybe user doesn't exist, create it
        reg_data = {
            "username": "testuser2",
            "email": "test2@example.com",
            "full_name": "Test User",
            "password": "testpassword123"
        }
        requests.post(f"{BASE_URL}/api/auth/register", json=reg_data)
        resp = requests.post(f"{BASE_URL}/api/auth/login", data=login_data)
    
    token = resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    print("--- Test 1: Revoke Document and Prevention of Sharing ---")
    # Register document
    doc_data = {"doc_type": "national_id", "fields": {"id_number": "123456", "full_name": "Test User"}}
    doc = requests.post(f"{BASE_URL}/api/identity/documents", json=doc_data, headers=headers).json()
    doc_id = doc["id"]
    print(f"Registered document: {doc_id}")

    # Revoke document
    requests.delete(f"{BASE_URL}/api/identity/documents/{doc_id}", headers=headers)
    print(f"Revoked document: {doc_id}")

    # Try to create grant
    grant_data = {
        "document_id": doc_id,
        "grantee_identifier": "verifier@gov.in",
        "fields_allowed": ["full_name"],
        "expires_hours": 24
    }
    grant_resp = requests.post(f"{BASE_URL}/api/access/grants", json=grant_data, headers=headers)
    print(f"Grant creation for revoked doc status: {grant_resp.status_code}")
    print(f"Error message: {grant_resp.json().get('detail')}")
    assert grant_resp.status_code == 400
    assert grant_resp.json().get('detail') == "Cannot grant access to a revoked document"

    print("\n--- Test 2: Revoke Grant and Blockchain Integration ---")
    # Register another document
    doc_data2 = {"doc_type": "passport", "fields": {"passport_no": "P987654", "name": "Global Traveler"}}
    doc2 = requests.post(f"{BASE_URL}/api/identity/documents", json=doc_data2, headers=headers).json()
    doc_id2 = doc2["id"]
    
    # Create grant
    grant_data2 = {
        "document_id": doc_id2,
        "grantee_identifier": "airport@terminal.com",
        "fields_allowed": ["name"],
        "expires_hours": 1
    }
    grant2 = requests.post(f"{BASE_URL}/api/access/grants", json=grant_data2, headers=headers).json()
    grant_id2 = grant2["id"]
    print(f"Created grant: {grant_id2}")

    # Revoke grant
    requests.delete(f"{BASE_URL}/api/access/grants/{grant_id2}", headers=headers)
    print(f"Revoked grant: {grant_id2}")

    # Check blockchain for REVOKE_GRANT transaction
    blocks = requests.get(f"{BASE_URL}/api/chain/blocks", headers=headers).json()
    last_block = blocks[-1]
    last_tx = last_block["transactions"][-1]
    print(f"Last transaction on chain: {last_tx['action']}")
    assert last_tx["action"] == "REVOKE_GRANT"
    assert last_tx["metadata"]["grant_id"] == grant_id2

    print("\nAll tests passed successfully!")

if __name__ == "__main__":
    test_revocation_flow()
