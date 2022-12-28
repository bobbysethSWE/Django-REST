# Blog post reference: https://www.codingforentrepreneurs.com/blog/python-jwt-client-django-rest-framework-simplejwt

from dataclasses import dataclass 
import requests
from getpass import getpass
import pathlib 
import json


@dataclass                    # JWT = JSON Web Token . Relatively large, only use if needed
class JWTClient:              # compact and self-contained way for securely transmitting information between parties as a JSON object.en 
    
    access:str = None         # dataclass decorator automatically generates special methods to classes ex :__str__ and __repr__
    refresh:str = None
    # ensure this matches your simplejwt config
    header_type: str = "Bearer"
    base_endpoint = "http://localhost:8000/api"   # this assumesy ou have DRF running on localhost:8000
    cred_path: pathlib.Path = pathlib.Path("creds.json") # this file path is insecure

    def __post_init__(self):        # post_init allows you to add custom logic to init
        if self.cred_path.exists(): 
                                          # You have stored creds, verify and refresh them. If that fails, restart login process
            try:
                data = json.loads(self.cred_path.read_text())    # json.loads = parse valid JSON string & convert it into a dict
            except Exception:
                print("Assuming creds has been tampered with")
                data = None
            if data is None:          # Clear stored creds and run login process
                self.clear_tokens()  # Token auth = exchanging user&pass for token used in later requests to identify a user (server side) 
                self.perform_auth()     
            else:                      # if creds.json not tampered with, veritfy token. If needed refresh token, if needed run login process
                self.access = data.get('access')
                self.refresh = data.get('refresh')
                token_verified = self.verify_token()
                if not token_verified:                  # either token is expired or invalid, regardless try refreshing
                    refreshed = self.perform_refresh()          # refresh tokens give access to a bunch of short lived access tokens
                    if not refreshed:                           # they're good, bc you don't have to reeneter creds (user/pass) constantly
                        """                                     
                        This means the token refresh
                        also failed. Run login process
                        """
                        print("invalid data, login again.")      # refresh tokens make users live easier since they don't have to constantly
                        self.clear_tokens()                      # keep logging in when access token times out
                        self.perform_auth()                      # basically instead of one long lived access token we use a combination
                                                                 # of multiple short lived access tokens and a refresh token to keep refreshing
        else:                                                    
            self.perform_auth()         # perform_auth() = runs the login process
        
    def get_headers(self, header_type=None):       # headers for HTTP requests, include JWT token in header/HTTP request
        _type = header_type or self.header_type
        token = self.access
        if not token:
            return {}
        return {
                "Authorization": f"{_type} {token}"
        }

    def perform_auth(self):            # performing authentication w.o exposing passwords during collection process
 
        endpoint = f"{self.base_endpoint}/token/" 
        username = input("What is your username?\n")
        password = getpass("What is your password?\n")       #getpass module prompts user for pass w.o echo (safe)
        r = requests.post(endpoint, json={'username': username, 'password': password}) 
        if r.status_code != 200:
            raise Exception(f"Access not granted: {r.text}")
        print('access granted')
        self.write_creds(r.json())

    def write_creds(self, data:dict):        # storing credentials as a local file, and updating instance with correct data
        if self.cred_path is not None:
            self.access = data.get('access')
            self.refresh = data.get('refresh')
            if self.access and self.refresh:
                self.cred_path.write_text(json.dumps(data))    # json.dumps() method can convert a Python object into a JSON string
    
    def verify_token(self):           # verifies only access token. 200 HTTP status = success. Anything else = failure
        data = {
            "token": f"{self.access}"
        }
        endpoint = f"{self.base_endpoint}/token/verify/" 
        r = requests.post(endpoint, json=data)
        return r.status_code == 200
    
    def clear_tokens(self):                   # remove all JWT token data from instance, also removes stored credentials file

        self.access = None
        self.refresh = None
        if self.cred_path.exists():
            self.cred_path.unlink()   
    
    def perform_refresh(self):                            # refresh access tokens by using correct authentication headers and refresh token
        print("Refreshing token.")
        headers = self.get_headers()
        data = {
            "refresh": f"{self.refresh}"
        }
        endpoint = f"{self.base_endpoint}/token/refresh/" 
        r = requests.post(endpoint, json=data, headers=headers)
        if r.status_code != 200:
            self.clear_tokens()
            return False
        refresh_data = r.json()
        if not 'access' in refresh_data:
            self.clear_tokens()
            return False
        stored_data = {
            'access': refresh_data.get('access'),
            'refresh': self.refresh
        }
        self.write_creds(stored_data)             # write_creds is a function 
        return True

    def list(self, endpoint=None, limit=3):
        """
        Here is an actual api call to a DRF
        View that requires our simplejwt Authentication
        Working correctly.
        """
        headers = self.get_headers()
        if endpoint is None or self.base_endpoint not in str(endpoint):
            endpoint = f"{self.base_endpoint}/products/?limit={limit}" 
        r = requests.get(endpoint, headers=headers)                       # get = HTTP, sents GET request to endpoint. Info sent = headers
        if r.status_code != 200:                                          # 200 = successful response, if not 200 = no/failed response
            raise Exception(f"Request not complete {r.text}")
        data = r.json()
        return data

if __name__ == "__main__":
    """
    Here's Simple example of how to use our client above.
    """
    
    # this will either prompt a login process
    # or just run with current stored data
    client = JWTClient() 

    # simple instance method to perform an HTTP
    # request to our /api/products/ endpoint
    lookup_1_data = client.list(limit=5)
    # We used pagination at our endpoint so we have:
    results = lookup_1_data.get('results')
    next_url = lookup_1_data.get('next')
    print("First lookup result length", len(results))
    if next_url:
        lookup_2_data = client.list(endpoint=next_url)
        results += lookup_2_data.get('results')
        print("Second lookup result length", len(results))