import re
from base64 import b64encode

def base64_encode_string(string):
    string = b64encode(str(string).encode('ascii'))
    return string.decode()

def sort_dict_alphabetical_keys(dictionary):
    new_dict = {}
    for sorted_key in sorted(dictionary.keys()):
        new_dict[sorted_key] = dictionary[sorted_key]
    return new_dict

def unwrap_response(response):
    status_code = response.status_code
    request_type = response.request.method
    request_url = response.request.url
    response_text = response.text
    return status_code, request_type, request_url, response_text

def validate_vault_secret(vault_secret):
    str_type_check = all(type(value) is str for value in vault_secret.secret_data.values())
    #check for dns valid name
    dns_match = re.fullmatch('([a-zA-Z\d]+[\.-]{0,1})+[a-zA-Z\d]+', vault_secret.secret_name) #None if not fullmatch
    #check keys
    keys_check = all(re.fullmatch('([\w]+[\.-]{0,1})+[\w]+', key) for key in vault_secret.secret_data.keys())
    #status_code check
    return all([str_type_check, dns_match, keys_check])

def get_pod_namespace():
    with open('/var/run/secrets/kubernetes.io/serviceaccount/namespace', 'r') as ns_file:
        namespace = ns_file.read()
    return namespace

def get_pod_jwt():
    with open('/var/run/secrets/kubernetes.io/serviceaccount/token', 'r') as jwt_file:
        jwt = jwt_file.read()
    return jwt