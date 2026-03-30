
import requests
import json

def test_validation_error():
    url = "http://127.0.0.1:8000/api/auth/register"
    payload = {
        "username": "err_test",
        "email": "not-an-email",
        "full_name": "Error Test",
        "password": "short"
    }
    headers = {"Content-Type": "application/json"}
    
    response = requests.post(url, data=json.dumps(payload), headers=headers)
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.text}")
    
    data = response.json()
    assert response.status_code == 422
    assert isinstance(data["detail"], str)
    assert "email" in data["detail"].lower()
    assert "password" in data["detail"].lower()
    
    print("Verification Successful: detail is a string and contains readable errors.")

if __name__ == "__main__":
    try:
        test_validation_error()
    except Exception as e:
        print(f"Verification Failed: {e}")
