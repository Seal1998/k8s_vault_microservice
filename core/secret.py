import logging
from core.helpers import base64_encode_string, sort_dict_alphabetical_keys
from kubernetes import client

class Secret:
    def __init__(self, secret_yml_data, secret_namespace, k8s_client):
        self.secret_yml_data = secret_yml_data
        self.secret_yml_data['data'] = sort_dict_alphabetical_keys(self.secret_yml_data['data'])
        self.secret_name = self.secret_yml_data['metadata']['name']
        self.namespace = secret_namespace
        self.k8s_client = k8s_client

        self.secret_to_update = False

        self.__encode_values()
        if self.__check_secret():
            pass
            #self.__create_secret()
    
    def __encode_values(self):
        for key, value in self.secret_yml_data['data'].items():
            self.secret_yml_data['data'][key] = base64_encode_string(value).decode()

    def __create_secret(self):
        try:
            self.k8s_client.create_namespaced_secret(self.namespace, body=self.secret_yml_data)
            logging.info('New Secret successfully created with name - %s, keys - %s', 
                                                self.secret_name)
        except client.exceptions.ApiException as err:
            print(err)

    def __check_secret(self):
        logging.info('Searching for existing secret with name - %s', self.secret_name)
        try:
            api_secret = self.k8s_client.read_namespaced_secret(namespace=self.namespace, name=self.secret_name)
            logging.warning('Secret %s exist. Checking values...', self.secret_name)
            if api_secret.data != self.secret_yml_data['data']:
                logging.info('Secrets values didn`t match. Updating secret...')
                self.secret_to_update = True
                return True
            else:
                logging.info('Secrets values are equel.Skipping...')
                return False
        except client.exceptions.ApiException as err:
            if 'NotFound' in str(err):
                logging.info('Secret %s doesn`t exist yet. Creating...', self.secret_name)
                return True