import re
from base64 import b64encode

def template_log_record(template_string, values_dict): #proccessing [[secret_name]] secret
    capture_keys_regexp = r'(?<=\[\[)[\w]+(?=\]\])'
    capture_template_pattern_regexp = r'\[\[[\w]+\]\]'

    string_els = {index: word for index,word in enumerate(template_string.split(' '))}
    keys_els = {index: re.search(capture_keys_regexp, word) for index,word in string_els.items() 
                                                            if re.search(capture_keys_regexp, word)}

    list(map(string_els.pop, keys_els.keys()))
    
    template_keys_templated = {index: re.sub(capture_template_pattern_regexp, values_dict[template_key.group()], template_key.string) 
                                                    for index,template_key in keys_els.items()}
    
    templated_string_els = {index: value for index,value in sorted({**string_els, **template_keys_templated}.items())}
    return ' '.join(templated_string_els.values())

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