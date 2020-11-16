from core.k8s_secret_operator import KubeSecretOperator
from core.decorators import Log

k8s_log = Log.create_k8s_logger()

class KubeInjector:

    def __init__(self, namespace, injector_id):
        self.injector_id = injector_id
        self.secret_op = KubeSecretOperator(namespace, labels_dict={'vault-injector': self.injector_id})
        self.all_secrets, self.managed_secrets = self.__get_all_and_managed_secrets()

    def __get_all_and_managed_secrets(self):
        return None, None