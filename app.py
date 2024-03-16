import os
import subprocess
import json
from flask import Flask, request, jsonify

app = Flask(__name__)

# Function to authenticate with Vault and return the token
def authenticate_with_vault():
    VAULT_ADDR = os.environ['VAULT_ADDR']
    VAULT_ROLE = os.environ['VAULT_ROLE']
    SA_TOKEN_PATH = '/var/run/secrets/kubernetes.io/serviceaccount/token'

    # Read the Service Account Token
    with open(SA_TOKEN_PATH, 'r') as token_file:
        sa_token = token_file.read().strip()

    # Construct the curl command
    login_cmd = f"curl -s --request POST --data '{{\"jwt\": \"{sa_token}\", \"role\": \"{VAULT_ROLE}\"}}' {VAULT_ADDR}/v1/auth/kubernetes/login"
    login_response = subprocess.run(login_cmd, shell=True, capture_output=True, text=True)

    # Parse the response to get the Vault token
    if login_response.returncode == 0:
        response_json = json.loads(login_response.stdout)
        vault_token = response_json['auth']['client_token']
        return vault_token
    else:
        return None

@app.route('/list-secrets')
def list_secrets():
    VAULT_ADDR = os.environ['VAULT_ADDR']
    vault_token = authenticate_with_vault()

    if vault_token:
        # Command to list secrets using the Vault token
        list_cmd = f'curl -s --header "X-Vault-Token: {vault_token}" --request LIST "{VAULT_ADDR}/v1/kv/metadata/"'
        list_response = subprocess.run(list_cmd, shell=True, capture_output=True, text=True)

        if list_response.returncode == 0:
            secrets_list = json.loads(list_response.stdout)
            return jsonify(secrets_list), 200
        else:
            return jsonify({"error": "Failed to list secrets", "details": list_response.stderr}), 500
    else:
        return jsonify({"error": "Authentication failed"}), 500

if __name__ == '__main__':
    app.run(debug=True)
