
import requests

def test_dual_login():
    url_reg = "http://127.0.0.1:8000/api/auth/register"
    url_login = "http://127.0.0.1:8000/api/auth/login"
    
    # Use unique data to avoid conflicts
    user_data = {
        "username": "login_test_user",
        "email": "login_test@example.com",
        "full_name": "Login Tester",
        "password": "testpassword123"
    }
    
    # 1. Register
    requests.post(url_reg, json=user_data)
    
    # 2. Test Login with Username
    print("Testing login with USERNAME...")
    resp_user = requests.post(url_login, data={"username": user_data["username"], "password": user_data["password"]})
    print(f"Status: {resp_user.status_code}")
    assert resp_user.status_code == 200
    assert resp_user.json()["username"] == user_data["username"]
    
    # 3. Test Login with Email
    print("\nTesting login with EMAIL...")
    resp_email = requests.post(url_login, data={"username": user_data["email"], "password": user_data["password"]})
    print(f"Status: {resp_email.status_code}")
    assert resp_email.status_code == 200
    assert resp_email.json()["username"] == user_data["username"]
    
    print("\nVerification Successful: Dual login (username/email) is working!")

if __name__ == "__main__":
    try:
        test_dual_login()
    except Exception as e:
        print(f"Verification Failed: {e}")
