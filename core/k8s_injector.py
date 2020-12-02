from core.k8s_secret_operator import KubeSecretOperator
from core.decorators import Log
from core.helpers import sort_dict_alphabetical_keys

k8s_log = Log.create_k8s_logger()

class KubeInjector:
    label_key = 'vault-injector'

    def __init__(self, namespace, injector_id):
        self.injector_id = injector_id
        self.injector_label_dict = {self.label_key:self.injector_id}
        self.secret_op = KubeSecretOperator(namespace)

        [   self.all_secrets, 
            self.injector_managed_secrets,
            self.any_injector_managed_secrets   ] = self.__get_all_and_managed_secrets()

    @k8s_log.info(msg='Getting all and managed secrets')
    def __get_all_and_managed_secrets(self):
        injector_managed_secrets = self.secret_op.list_secrets(label_dict=self.injector_label_dict)
        any_injector_managed_secrets = self.secret_op.list_secrets(label_key=self.label_key)
        all_secrets = self.secret_op.list_secrets()
        return tuple(secret.metadata.name for secret in all_secrets), \
                list(secret.metadata.name for secret in injector_managed_secrets), \
                tuple(secret.metadata.name for secret in any_injector_managed_secrets)
    
    def __secrets_equivalence(self, first_secret_data, second_secret_data):
        first_secret_data = sort_dict_alphabetical_keys(first_secret_data)
        second_secret_data = sort_dict_alphabetical_keys(second_secret_data)
        return first_secret_data == second_secret_data

    @k8s_log.info(msg='Processing [[[secret_name]]] secret', template_kvargs=True, print_return=True)
    def upload_secret(self, secret_name, secret_data):
        if secret_name not in self.all_secrets:
            self.secret_op.create_secret(secret_name=secret_name, data_dict=secret_data, label_dict=self.injector_label_dict)
            return f'Secret successfully created. Keys - {str([key for key in secret_data.keys()])}'

        else:
            existing_secret = self.secret_op.get_secret(secret_name=secret_name)
            if secret_name in self.any_injector_managed_secrets:
                if secret_name not in self.injector_managed_secrets:
                    replaced_labels_dict = existing_secret.metadata.labels
                else:
                    replaced_labels_dict = self.injector_label_dict
                    #removing secret from injector managed list
                    self.injector_managed_secrets.remove(secret_name)

                if self.__secrets_equivalence(existing_secret.data, secret_data):
                    return 'The secret already exists and has not changed'
                else:
                    self.secret_op.replace_secret(secret_name=secret_name, data_dict=secret_data, 
                                                    label_dict=replaced_labels_dict)
                    return f'Secret exists and replaced with new version. Keys - {str([key for key in secret_data.keys()])}'
            else:
                replaced_labels_dict = self.injector_label_dict
                self.secret_op.replace_secret(secret_name=secret_name, data_dict=existing_secret.data, 
                                                                label_dict=replaced_labels_dict)
                return 'Secret exists but do not managing by any vault-injector. Labling with current vault-injector labels'
    
    @k8s_log.info(msg='Launching unprocessed secrets removal...', print_return=True)
    def remove_unprocessed_secrets(self):
        if len(self.injector_managed_secrets) == 0:
            return 'Nothing to remove. Done'
        list(map(lambda name: self.secret_op.delete_secret(secret_name=name), self.injector_managed_secrets))
        return 'Done'