import os
import requests
from flask import Flask, request, jsonify, render_template
import hvac
import logging

app = Flask(__name__)
logging.basicConfig(level=logging.DEBUG)

# Environment variables
VAULT_ADDR = os.environ['VAULT_ADDR']
VAULT_ROLE = os.environ['VAULT_ROLE']
VAULT_TOKEN = None  # This will store the Vault token globally

def authenticate_with_vault():
    global VAULT_TOKEN
    jwt_token_path = '/var/run/secrets/kubernetes.io/serviceaccount/token'
    with open(jwt_token_path, 'r') as token_file:
        jwt_token = token_file.read().strip()

    data = {"jwt": jwt_token, "role": VAULT_ROLE}
    headers = {'Content-Type': 'application/json'}
    login_url = f"{VAULT_ADDR}/v1/auth/kubernetes/login"
    response = requests.post(login_url, json=data, headers=headers)
    if response.ok:
        VAULT_TOKEN = response.json()['auth']['client_token']
        app.logger.debug("Vault authentication successful.")
    else:
        app.logger.error("Vault authentication failed.")

authenticate_with_vault()

# Initialize HVAC client with the token
client = hvac.Client(url=VAULT_ADDR, token=VAULT_TOKEN)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/store-secret', methods=['POST'])
def store_secret():
    secret_path = request.json['path']
    secret_data = request.json['data']
    try:
        client.secrets.kv.v2.create_or_update_secret(path=secret_path, secret=secret_data)
        return jsonify({"success": True}), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/list-secrets', methods=['GET'])
def list_secrets():
    # Fixed path to align with your correct URL for listing
    parent_path = "kv/metadata/"
    app.logger.debug(f"Attempting to list secrets at path: '{parent_path}'")

    try:
        list_response = client.secrets.kv.v2.list_secrets(path=parent_path)
        app.logger.debug(f"Successfully listed secrets at path: '{parent_path}'. Response: {list_response}")
        return jsonify(list_response['data']), 200
    except Exception as e:
        app.logger.error(f"Error listing secrets at path: '{parent_path}'. Error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
