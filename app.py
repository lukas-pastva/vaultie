import os
from flask import Flask, request, jsonify, render_template
import hvac
import logging

app = Flask(__name__)

# Set up basic configuration for logging
logging.basicConfig(level=logging.DEBUG)

# Environment variables
vault_addr = os.environ['VAULT_ADDR']
vault_role = os.environ['VAULT_ROLE']

client = hvac.Client(url=vault_addr)

# Authenticate with Vault using the Kubernetes auth method
def authenticate_with_vault():
    with open('/var/run/secrets/kubernetes.io/serviceaccount/token', 'r') as token_file:
        jwt_token = token_file.read().strip()
    # Log the token for debugging purposes
    app.logger.debug(f"JWT Token: {jwt_token}")

    try:
        client.auth.kubernetes.login(role=vault_role, jwt=jwt_token)
    except Exception as e:
        app.logger.error(f"Vault authentication failed: {e}")

authenticate_with_vault()

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
    parent_path = request.args.get('parent', '')
    try:
        list_response = client.secrets.kv.v2.list_secrets(path=parent_path)
        return jsonify(list_response['data']), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
