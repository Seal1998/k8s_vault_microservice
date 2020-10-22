import jinja2
import os, sys
import yaml, json
import logging
from kubernetes import config, client, utils
from pathlib import Path
from core.helpers import base64_encode_string, get_pod_namespace
from core.secret import Secret


#TEMPLATE_PATH,SECRETS_PATH

#system globals
env = os.environ
templates_path = Path(env['TEMPLATE_PATH'])
secrets_path = Path(env['SECRETS_PATH'])
logs_path = Path(env['LOG_FILE_PATH'])

namespace = get_pod_namespace(non_k8s='default')

#logs options
formatter_string = '%(asctime)s - %(levelname)s - %(message)s'
formatter = logging.Formatter(formatter_string)
logging.basicConfig(filename=logs_path, format=formatter_string, level=logging.INFO)
stdout_handler = logging.StreamHandler(sys.stdout)
stdout_handler.setFormatter(formatter)
root_logger = logging.getLogger()
root_logger.addHandler(stdout_handler)


#k8s globals
config.load_kube_config()
k8s_v1 = client.CoreV1Api()

file_template_loader = jinja2.FileSystemLoader(searchpath=templates_path)
template_env = jinja2.Environment(loader=file_template_loader)
secret_template = template_env.get_template('Secret.j2')

k8s_rendered_secrets = []

for secret in secrets_path.iterdir():
    with open(secret, 'r') as stream:
        secret_yml = yaml.safe_load(stream)
        Secret(
            yaml.safe_load(secret_template.render(secret_name=str(secret).split('/')[-1:][0], secrets_dict=secret_yml)),
            namespace,
            k8s_v1
        )    