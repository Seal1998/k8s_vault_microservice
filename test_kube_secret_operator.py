#from kubernetes import config
#from core import KubeInjector
import logging
from core.decorators import Log
from core.exceptions import VaultException

def ex_handler(ex):
    print(ex)

a = Log.create_vault_logger()

@a.info(msg='test [[a]]', template_kvargs=True, on_success='OK', print_return=True, on_error='Bad luck...')
def print_a(a):
    if a == 1:
        raise VaultException(401, 'GET', 'https://google.com', 'Get lost')
    return a

print_a(a=1)