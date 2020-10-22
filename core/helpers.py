from base64 import b64encode

def base64_encode_string(string):
    string = b64encode(str(string).encode('ascii'))
    return string

def sort_dict_alphabetical_keys(dictionary):
    new_dict = {}
    for sorted_key in sorted(dictionary.keys()):
        new_dict[sorted_key] = dictionary[sorted_key]
    return new_dict

def get_pod_namespace():
    with open('/var/run/secrets/kubernetes.io/serviceaccount/namespace', 'r') as ns_file:
        namespace = ns_file.read()
    return namespace

def get_pod_jwt():
    with open('/var/run/secrets/kubernetes.io/serviceaccount/token', 'r') as jwt_file:
        jwt = ns_file.read()
    return jwt