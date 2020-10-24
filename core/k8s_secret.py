import logging
import yaml
import jinja2
from core.helpers import base64_encode_string, sort_dict_alphabetical_keys
from kubernetes import client

templates_path = './core/templates'

class k8s_Secret:
    namespace = None
    secret_template = None

    def __init__(self, secret_yml_data):
        self.secret_yml_data = secret_yml_data
        self.secret_yml_data['data'] = sort_dict_alphabetical_keys(self.secret_yml_data['data'])
        self.secret_name = self.secret_yml_data['metadata']['name']
        
        self.k8s_CoreV1_client = client.CoreV1Api()
        self.k8s_AuthenticationV1_client = client.AuthenticationV1Api()
        
        self.secret_to_update = False
        self.secret_to_replace = False

        self.__encode_values()
        if self.__check_secret():
            self.__create_secret()

    @classmethod
    def prepare_connection(cls, namespace):
        cls.namespace = namespace
        cls.load_secret_template()
        cls.check_token_permissions()

    @classmethod
    def load_secret_template(cls):
        file_template_loader = jinja2.FileSystemLoader(searchpath=templates_path)
        template_env = jinja2.Environment(loader=file_template_loader)
        cls.secret_template = template_env.get_template('Secret.j2')

    @classmethod
    def upload_vault_secret(cls, vault_secret):
        logging.info(f'K8S | Uploading {vault_secret.secret_name} ...')
        rendered_vault_secret_data = yaml.safe_load(
            cls.secret_template.render(secret_name=vault_secret.secret_name, secrets_dict=vault_secret.secret_data)
        )
        cls(secret_yml_data=rendered_vault_secret_data)

    @classmethod
    def check_token_permissions(cls):
        logging.info('K8S | Checking token permissions for Secret resource...')
        try:
            secrets = client.CoreV1Api().list_namespaced_secret(namespace=cls.namespace)
            logging.info('K8S | LIST OK')
        except:
            logging.error('K8S | LIST - failed. Injector can`t list secrets')
            exit(1)
        try:
            client.CoreV1Api().read_namespaced_secret(namespace=cls.namespace, name=secrets.items[0].metadata.name)
            logging.info('K8S | READ - OK')
        except:
            logging.error('K8S | READ - failed. Injector can`t read secrets')
            exit(1)
        try:
            test_yaml_secret = yaml.safe_load(cls.secret_template.render(secret_name='test-injector-secret', secrets_dict={'test': 'secret'}))
            cls(secret_yml_data=test_yaml_secret)
            logging.info('K8S | CREATE - OK')
        except:
            logging.error('K8S | CREATE - failed. Injector can`t create secrets')
            exit(1)
        try:
            secrets = client.CoreV1Api().delete_namespaced_secret(namespace=cls.namespace, name=test_yaml_secret['metadata']['name'])
            logging.info('K8S | DELETE - OK')
        except:
            logging.error('K8S | DELETE - failed. Injector can`t create secrets')
            exit(1)

    def __encode_values(self):
        for key, value in self.secret_yml_data['data'].items():
            self.secret_yml_data['data'][key] = base64_encode_string(value).decode()

    def __create_secret(self):
        if self.secret_to_replace:
            try:
                self.k8s_CoreV1_client.replace_namespaced_secret(namespace=self.namespace, body=self.secret_yml_data, name=self.secret_name)
                logging.info('K8S | %s | Secret successfully replaced with new values. Keys - %s', 
                                                    self.secret_name, ", ".join([key for key in self.secret_yml_data['data'].keys()]))
            except client.exceptions.ApiException as err:
                print(err) 
        elif self.secret_to_update:
            try:
                self.k8s_CoreV1_client.patch_namespaced_secret(namespace=self.namespace, body={'data': self.secret_yml_data['data']}, name=self.secret_name)
                logging.info('K8S | %s | Secret successfully updated with new values. Keys - %s', 
                                                    self.secret_name, ", ".join([key for key in self.secret_yml_data['data'].keys()]))
            except client.exceptions.ApiException as err:
                print(err)    
        else:
            try:
                self.k8s_CoreV1_client.create_namespaced_secret(self.namespace, body=self.secret_yml_data)
                logging.info('K8S | %s |  New Secret successfully created. Keys - %s', 
                                                    self.secret_name, ", ".join([key for key in self.secret_yml_data['data'].keys()]))
            except client.exceptions.ApiException as err:
                print(err)

    def __check_secret(self):
        api_secret = self.k8s_CoreV1_client.list_namespaced_secret(namespace=self.namespace)
        logging.info('K8S | %s | Searching for existing secret', self.secret_name)
        try:
            api_secret = self.k8s_CoreV1_client.read_namespaced_secret(namespace=self.namespace, name=self.secret_name)
            logging.warning('K8S | %s | Secret exist. Checking values...', self.secret_name)
            if api_secret.data != self.secret_yml_data['data']:
                if len(api_secret.data) != len(self.secret_yml_data['data']):
                    logging.info('K8S | %s | Data block of original secret has different size. Replacing secret...', self.secret_name)
                    self.secret_to_replace = True
                else:
                    logging.info('K8S | %s | Secrets values didn`t match. Updating secret...', self.secret_name)
                    self.secret_to_update = True
                return True
            else:
                logging.info('K8S | %s | Secrets values are equel.Skipping...', self.secret_name)
                return False
        except client.exceptions.ApiException as err:
            if 'NotFound' in str(err):
                logging.info('K8S | %s | Secret doesn`t exist yet. Creating...', self.secret_name)
                return True