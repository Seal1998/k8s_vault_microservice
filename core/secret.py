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
        self.secret_to_replace = False

        self.__encode_values()
        if self.__check_secret():
            self.__create_secret()
    
    def __encode_values(self):
        for key, value in self.secret_yml_data['data'].items():
            self.secret_yml_data['data'][key] = base64_encode_string(value).decode()

    def __create_secret(self):
        if self.secret_to_replace:
            try:
                self.k8s_client.replace_namespaced_secret(namespace=self.namespace, body=self.secret_yml_data, name=self.secret_name)
                logging.info(' %s | Secret successfully replaced with new values. Keys - %s', 
                                                    self.secret_name, ", ".join([key for key in self.secret_yml_data['data'].keys()]))
            except client.exceptions.ApiException as err:
                print(err) 
        elif self.secret_to_update:
            try:
                self.k8s_client.patch_namespaced_secret(namespace=self.namespace, body={'data': self.secret_yml_data['data']}, name=self.secret_name)
                logging.info(' %s | Secret successfully updated with new values. Keys - %s', 
                                                    self.secret_name, ", ".join([key for key in self.secret_yml_data['data'].keys()]))
            except client.exceptions.ApiException as err:
                print(err)    
        else:
            try:
                self.k8s_client.create_namespaced_secret(self.namespace, body=self.secret_yml_data)
                logging.info(' %s | New Secret successfully created. Keys - %s', 
                                                    self.secret_name, ", ".join([key for key in self.secret_yml_data['data'].keys()]))
            except client.exceptions.ApiException as err:
                print(err)

    def __check_secret(self):
        logging.info(' %s | Searching for existing secret', self.secret_name)
        try:
            api_secret = self.k8s_client.read_namespaced_secret(namespace=self.namespace, name=self.secret_name)
            logging.warning(' %s | Secret exist. Checking values...', self.secret_name)
            if api_secret.data != self.secret_yml_data['data']:
                if len(api_secret.data) != len(self.secret_yml_data['data']):
                    logging.info(' %s | Data block of original secret has different size. Replacing secret...', self.secret_name)
                    self.secret_to_replace = True
                else:
                    logging.info(' %s | Secrets values didn`t match. Updating secret...', self.secret_name)
                    self.secret_to_update = True
                return True
            else:
                logging.info(' %s | Secrets values are equel.Skipping...', self.secret_name)
                return False
        except client.exceptions.ApiException as err:
            if 'NotFound' in str(err):
                logging.info(' %s | Secret doesn`t exist yet. Creating...', self.secret_name)
                return True