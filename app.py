import os
import subprocess
from flask import Flask, request, jsonify, render_template
import logging
import json

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

    login_cmd = f"curl -s --request POST --data '{{\"jwt\": \"{jwt_token}\", \"role\": \"{VAULT_ROLE}\"}}' {VAULT_ADDR}/v1/auth/kubernetes/login"
    login_response = subprocess.run(login_cmd, shell=True, capture_output=True, text=True)

    if login_response.returncode == 0 and "client_token" in login_response.stdout:
        VAULT_TOKEN = subprocess.run("echo '{}' | jq -r '.auth.client_token'".format(login_response.stdout), shell=True, capture_output=True, text=True).stdout.strip()
        app.logger.debug("Vault authentication successful.")
    else:
        app.logger.error(f"Vault authentication failed. Response: {login_response.stdout}, Error: {login_response.stderr}")

authenticate_with_vault()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/list-secrets', methods=['GET'])
def list_secrets():
    parent_path = request.args.get('parent', '')
    app.logger.debug(f"Attempting to list secrets at path: '{parent_path}'")
    try:
        list_cmd = f"curl -s --header \"X-Vault-Token: {VAULT_TOKEN}\" {VAULT_ADDR}/v1/secret/metadata/{parent_path}?list=true"
        list_response = subprocess.run(list_cmd, shell=True, capture_output=True, text=True)
        if list_response.returncode == 0:
            try:
                # Attempt to parse the JSON response
                secrets_list = json.loads(list_response.stdout)
                app.logger.debug(f"Successfully listed secrets at path: '{parent_path}'. Response: {secrets_list}")
                return jsonify(secrets_list), 200
            except json.JSONDecodeError:
                # Log and handle JSON parsing error
                app.logger.error(f"Failed to parse JSON response. Response: {list_response.stdout}")
                return jsonify({"success": False, "error": "Failed to parse JSON response."}), 500
        else:
            # Log stderr when the command fails
            app.logger.error(f"Failed to list secrets. Response: {list_response.stdout}, Error: {list_response.stderr}")
            return jsonify({"success": False, "error": list_response.stderr}), 500
    except Exception as e:
        app.logger.error(f"Error listing secrets at path: '{parent_path}'. Exception: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)