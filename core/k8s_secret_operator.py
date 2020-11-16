import yaml
import jinja2
import random
from core.decorators import Log
from core.helpers import base64_encode_string, sort_dict_alphabetical_keys
from kubernetes import client

k8s_log = Log.create_k8s_logger()

class KubeSecretOperator:

    def __init__(self, namespace, labels_dict):
        self.API_CoreV1 = client.CoreV1Api()

        self.namespace = namespace
        self.labels_dict = labels_dict

        self.tpl_env = self.__get_template_env()

        self.check_permissions()

    @k8s_log.info(msg='Checking K8S permissions...', on_success='Permissions - OK', fatal=True)
    def check_permissions(self):
        listed_secrets = self.list_secrets()
        first_secret_name = listed_secrets.items[0].metadata.name

        self.get_secret(secret_name=first_secret_name)
        
        test_secret_name = f'test-secret-{random.randint(0, 2**20)}'
        self.create_secret(secret_name=test_secret_name, data_dict={'test': 'secret'})

        test_secret_replace_dict = {'replace': 'test'}
        self.replace_secret(secret_name=test_secret_name, data_dict=test_secret_replace_dict)
        self.delete_secret(secret_name=test_secret_name)

    @k8s_log.info(msg='Listing namespace secrets')
    def list_secrets(self):
        listed_secrets = self.API_CoreV1.list_namespaced_secret(self.namespace)
        return listed_secrets

    @k8s_log.info(msg='Getting [[secret_name]] secret', template_kvargs=True)
    def get_secret(self, secret_name):
        self.API_CoreV1.read_namespaced_secret(namespace=self.namespace, name=secret_name)

    @k8s_log.info(msg='Creating [[secret_name]] secret', template_kvargs=True)
    def create_secret(self, secret_name, data_dict):
        data_dict = self.__encode_data(data_dict)
        loaded_yml = self.__render_secret_template(secret_name=secret_name, 
                                data_dict=data_dict, return_loaded_yml=True)
        created_secret = self.API_CoreV1.create_namespaced_secret(self.namespace, loaded_yml)
        return created_secret

    @k8s_log.info(msg='Deleting [[secret_name]] secret', template_kvargs=True)
    def delete_secret(self, secret_name):
        self.API_CoreV1.delete_namespaced_secret(secret_name, self.namespace)

    @k8s_log.info(msg='Replacing [[secret_name]] secret', template_kvargs=True)
    def replace_secret(self, secret_name, data_dict):
        secret_to_replace = self.__render_secret_template(secret_name=secret_name, 
                                     data_dict=data_dict, return_loaded_yml=True)
        replaced_secret = self.API_CoreV1.replace_namespaced_secret(secret_name, self.namespace, secret_to_replace)
        return replaced_secret

    def patch_secret(self, secret_name):
        pass

    @k8s_log.info(msg='Rendering secret with name [[secret_name]]', template_kvargs=True)
    def __render_secret_template(self, *, secret_name=None, data_dict=None, return_loaded_yml=False,
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