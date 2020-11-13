import yaml
import jinja2
import random
from core import k8s_logger
from core.helpers import base64_encode_string, sort_dict_alphabetical_keys
from kubernetes import client

class KubeSecretOperator:

    def __init__(self, namespace, labels_dict):
        self.API_CoreV1 = client.CoreV1Api()

        self.namespace = namespace
        self.labels_dict = labels_dict

        self.tpl_env = self.__get_template_env()

        self.check_permissions()

    def check_permissions(self):
        listed_secrets = self.list_secrets()
        first_secret_name = listed_secrets.items[0].metadata.name

        self.get_secret(first_secret_name)
        
        test_secret_name = f'test-secret-{random.randint(0, 2**20)}'
        self.create_secret(test_secret_name, {'test': 'secret'})

        test_secret_to_replace = self.__render_secret_template(test_secret_name, {'replace': 'test'}, 
                                                                                    return_loaded_yml=True)
        self.replace_secret(test_secret_name, test_secret_to_replace)
        self.delete_secret(test_secret_name)

    def list_secrets(self):
        listed_secrets = self.API_CoreV1.list_namespaced_secret(self.namespace)
        return listed_secrets

    def get_secret(self, secret_name):
        self.API_CoreV1.read_namespaced_secret(namespace=self.namespace, name=secret_name)

    def create_secret(self, secret_name, data_dict):
        data_dict = self.__encode_data(data_dict)
        loaded_yml = self.__render_secret_template(secret_name, data_dict, return_loaded_yml=True)
        created_secret = self.API_CoreV1.create_namespaced_secret(self.namespace, loaded_yml)
        return created_secret

    def delete_secret(self, secret_name):
        self.API_CoreV1.delete_namespaced_secret(secret_name, self.namespace)

    def replace_secret(self, secret_name, loaded_secret):
        replaced_secret = self.API_CoreV1.replace_namespaced_secret(secret_name, self.namespace, loaded_secret)
        return replaced_secret

    def patch_secret(self, secret_name):
        pass

    def __render_secret_template(self, secret_name, data_dict, return_loaded_yml=False,
                                    secret_tpl_name='Secret.j2'):

        secret_template = self.tpl_env.get_template(secret_tpl_name)
        yml_raw_string = secret_template.render(secret_name=secret_name, data_dict=data_dict, label_dict=self.labels_dict)

        if not return_loaded_yml:
            return yml_raw_string
        else:
            return yaml.safe_load(yml_raw_string)

    def __get_template_env(self, templates_path='./core/templates'):
        file_template_loader = jinja2.FileSystemLoader(searchpath=templates_path)
        template_env = jinja2.Environment(loader=file_template_loader)
        return template_env
    
    def __encode_data(self, secret_data):
        encoded_dict = {key: base64_encode_string(val) for key, val in secret_data.items()}
        return encoded_dict