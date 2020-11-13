from kubernetes import config
from core import KubeInjector
from core.helpers import template_log_record

config.load_kube_config()

a = template_log_record('Secret [[[secret_name]]] proccessed. [[result]]', {'secret_name':'secret1', 'result': 'OK'})
print(a)
#KubeInjector('default', 'test')