import yaml
import jinja2
import re
from core import k8s_logger
from core.helpers import base64_encode_string, sort_dict_alphabetical_keys
from kubernetes import client

templates_path = './core/templates'


class k8s_Secret:
    namespace = None
    secret_template = None
    vault_injector_id = None
    managed_secrets = {}
    all_secrets = {}

    #api objects
    k8s_CoreV1_client = None #WTF
    k8s_AuthenticationV1_client = None

    def __init__(self, secret_yml_data):
        self.secret_yml_data = secret_yml_data
        self.secret_yml_data['data'] = sort_dict_alphabetical_keys(self.secret_yml_data['data'])
        self.secret_name = self.secret_yml_data['metadata']['name']
        
        #action flags
        self.secret_to_update = False
        self.secret_to_replace = False
        self.secret_to_create = False
        self.secret_to_skip = False

        self.secret_is_valid = True

        self.__encode_values()
        self.__check_secret()
        if not self.secret_to_skip and self.secret_is_valid:
            self.__proceed_secret()

    @classmethod
    def prepare_connection(cls, namespace, injector_id):
        cls.namespace = namespace
        # if vault injector value not provided, namespace name will be used
        cls.vault_injector_id = injector_id

        cls.k8s_CoreV1_client = client.CoreV1Api()

        #prepare jinja2 template
        file_template_loader = jinja2.FileSystemLoader(searchpath=templates_path)
        template_env = jinja2.Environment(loader=file_template_loader)
        cls.secret_template = template_env.get_template('Secret.j2')

        cls.check_token_permissions()

        #get all secrets and vault managed
        k8s_logger.info('Getting injector managed secrets...')
        all_secrets_raw = cls.k8s_CoreV1_client.list_namespaced_secret(cls.namespace)
        
        #construct dicts of all and managed secrets where key - secret name and value - V1Secret
        for secret in all_secrets_raw.items:
            cls.all_secrets[secret.metadata.name] = secret
            if secret.metadata.labels != None and \
                    'vault-injector' in secret.metadata.labels.keys() and \
                    secret.metadata.labels['vault-injector'] == cls.vault_injector_id:
                cls.managed_secrets[secret.metadata.name] = secret


    @classmethod
    def upload_vault_secret(cls, vault_secret):
        k8s_logger.info(f'Uploading {vault_secret.secret_name} ...')

        rendered_vault_secret_data = yaml.safe_load(
            cls.secret_template.render(
                                    secret_name=vault_secret.secret_name, 
                                    secrets_dict=vault_secret.secret_data,
                                    injector_id=cls.vault_injector_id
                                    )
        )
        cls(secret_yml_data=rendered_vault_secret_data)

    @classmethod
    def check_token_permissions(cls):
        k8s_logger.info('Checking token permissions for Secret resource...')
        try:
            secrets = client.CoreV1Api().list_namespaced_secret(namespace=cls.namespace)
            k8s_logger.info('LIST OK')
        except:
            k8s_logger.error('LIST - failed. Injector can`t list secrets')
            exit(1)
        try:
            client.CoreV1Api().read_namespaced_secret(namespace=cls.namespace, name=secrets.items[0].metadata.name)
            k8s_logger.info('READ - OK')
        except:
            k8s_logger.error('READ - failed. Injector can`t read secrets')
            exit(1)
        try:
            test_yaml_secret = yaml.safe_load(cls.secret_template.render(secret_name=f'test-injector-secret-{cls.vault_injector_id}', 
                                                                        secrets_dict={'test': 'secret'},
                                                                        injector_id=cls.vault_injector_id))
            cls(secret_yml_data=test_yaml_secret)
            k8s_logger.info('CREATE - OK')
        except:
            k8s_logger.error('CREATE - failed. Injector can`t create secrets')
            exit(1)
        try:
            secrets = client.CoreV1Api().delete_namespaced_secret(namespace=cls.namespace, name=test_yaml_secret['metadata']['name'])
            k8s_logger.info('DELETE - OK')
        except:
            k8s_logger.error('DELETE - failed. Injector can`t create secrets')
            exit(1)

    def __encode_values(self):
        for key, value in self.secret_yml_data['data'].items():
            self.secret_yml_data['data'][key] = base64_encode_string(value).decode()

    def __proceed_secret(self):
        if self.secret_to_replace:
            try:
                self.k8s_CoreV1_client.replace_namespaced_secret(namespace=self.namespace, body=self.secret_yml_data, name=self.secret_name)
                k8s_logger.info('%s | Secret successfully replaced with new values. Keys - %s', 
                                                    self.secret_name, ", ".join([key for key in self.secret_yml_data['data'].keys()]))
            except client.exceptions.ApiException as err:
                print(err) 
        elif self.secret_to_update:
            try:
                self.k8s_CoreV1_client.patch_namespaced_secret(namespace=self.namespace, body={'data': self.secret_yml_data['data']}, name=self.secret_name)
                k8s_logger.info('%s | Secret successfully updated with new values. Keys - %s', 
                                                    self.secret_name, ", ".join([str(key) for key in self.secret_yml_data['data'].keys()]))
            except client.exceptions.ApiException as err:
                print(err)    
        elif self.secret_to_create:
            try:
                self.k8s_CoreV1_client.create_namespaced_secret(self.namespace, body=self.secret_yml_data)
                k8s_logger.info('%s |  New Secret successfully created. Keys - %s', 
                                                    self.secret_name, ", ".join([key for key in self.secret_yml_data['data'].keys()]))
            except client.exceptions.ApiException as err:
                print(err)

    def __remove_candidate_for_deletion(self, k8s_secret_name, policy='default'):
        if k8s_secret_name in k8s_Secret.managed_secrets.keys():
            k8s_logger.info(f'Secret {k8s_secret_name} is managed by this injector instance')
            del k8s_Secret.managed_secrets[k8s_secret_name]
            return True
        else:
            non_managed_secret = k8s_Secret.all_secrets[k8s_secret_name]
            non_managed_secret_labels = non_managed_secret.metadata.labels
            if non_managed_secret_labels != None and \
                'vault-injector' in non_managed_secret_labels.keys():
                    another_injector_id = non_managed_secret_labels['vault-injector']
                    if policy == 'default':
                        k8s_logger.warning(f'Secret {k8s_secret_name} is managed by injector instance with id [{another_injector_id}]. Keeping old injector label')
                        self.secret_yml_data['metadata']['labels']['managed-by'] = non_managed_secret_labels['vault-injector']
                    elif policy == 'agressive':
                        k8s_logger.warning(f'Relabeling {k8s_secret_name} because of agressive policy - [{another_injector_id} -> {self.vault_injector_id}]')
                        self.__label_secret_with_injector_key(k8s_secret_name)
                    #if skip - nothing will be done, if replace - old label will be kept, update - only body changes
            else:
                k8s_logger.info(f'Secret {k8s_secret_name} do not manage by vault-injector. Injector labels will be added')
                self.__label_secret_with_injector_key(k8s_secret_name)
                #Save old labels, add add vault-injector labels
    
    def __label_secret_with_injector_key(self, k8s_secret_name):
        k8s_logger.info(f'Labeling secret {k8s_secret_name} with injector values')
        unlabled_secret = self.all_secrets[k8s_secret_name]
        self.k8s_CoreV1_client.patch_namespaced_secret(namespace=self.namespace, name=unlabled_secret.metadata.name, 
                                                                                body={'metadata': {
                                                                                        'labels': {
                                                                                            'vault-injector': self.vault_injector_id
                                                                                                    }
                                                                                                }
                                                                                        })
    @classmethod
    def remove_untrackable_secrets(cls):
        for secret in cls.managed_secrets.keys():
            k8s_logger.info(f'Removing {secret} secret from k8s because it was deleted from Vault or paths map')
            try:
                cls.k8s_CoreV1_client.delete_namespaced_secret(namespace=cls.namespace, name=secret)
            except client.exceptions.ApiException as err:
                print(err)

    def __check_secret(self):
        k8s_logger.info('%s | Searching for existing secret', self.secret_name)
        if self.secret_name in self.all_secrets.keys():
            k8s_logger.warning('%s | Secret exist. Checking values...', self.secret_name)
            existing_secret = self.all_secrets[self.secret_name]
            if existing_secret.data != self.secret_yml_data['data']:
                if len(existing_secret.data) != len(self.secret_yml_data['data']):
                    k8s_logger.info('%s | Data block of original secret has different size. Secret will be replaced', self.secret_name)
                    self.__remove_candidate_for_deletion(existing_secret.metadata.name)
                    self.secret_to_replace = True
                else:
                    k8s_logger.info('%s | Secrets values didn`t match. Secret will be updated', self.secret_name)
                    self.__remove_candidate_for_deletion(existing_secret.metadata.name)
                    self.secret_to_update = True
            else:
                k8s_logger.info('%s | Secrets values are equal. Secret will be skipped', self.secret_name)
                self.__remove_candidate_for_deletion(existing_secret.metadata.name)
                self.secret_to_skip = True
        else:
            k8s_logger.info('%s | Secret doesn`t exist yet. Creating...', self.secret_name)
            self.secret_to_create = True