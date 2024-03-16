from flask import Flask, request, jsonify, render_template
import hvac
import os

app = Flask(__name__)

# Connect to Vault
vault_addr = os.environ['VAULT_ADDR']

client = hvac.Client(url=vault_addr)

# Authenticate with Vault using the Kubernetes auth method
def authenticate_with_vault():
    service_account_name = open('/var/run/secrets/kubernetes.io/serviceaccount/service-account.name').read().strip()
    jwt_token = open('/var/run/secrets/kubernetes.io/serviceaccount/token', 'r').read()
    client.auth_kubernetes(service_account_name, jwt_token)

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