# vaultie
- Web that will let you insrt secrets into hashicorp vault.
- The reason forhaving this is, that user is not havinyg any Vault token, and this web lets him only ability to inserts secrets, not udpate or delete.
- Required to set policy for Vault
```bash
path "kv/data/*" {
  capabilities = ["create"]
}

path "kv/metadata/*" {
  capabilities = ["list"]
} 
```
- To set Vault kubernetes authentication
```sql
vault write auth/kubernetes/role/sys-saas-web-secrets \
     bound_service_account_names=sys-saas-web-secrets \
     bound_service_account_namespaces=sys-saas-web-secrets \
     policies=sys-saas-web-secrets/sys-saas-web-secrets \
     ttl=6000h
```