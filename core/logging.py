import logging

#logging conf
vault_logger = logging.getLogger('__vault__')
k8s_logger = logging.getLogger('__k8s__')
system_logger = logging.getLogger('__system__')

vault_stream = logging.StreamHandler()
k8s_stream = logging.StreamHandler()
system_stream = logging.StreamHandler()

vault_formatter = logging.Formatter('%(asctime)s - %(levelname)s - | HVAULT | %(message)s')
k8s_formatter = logging.Formatter('%(asctime)s - %(levelname)s - | K8S | %(message)s')
system_formatter = logging.Formatter('%(asctime)s - %(levelname)s - | SYSTEM | %(message)s')

vault_stream.setFormatter(vault_formatter)
k8s_stream.setFormatter(k8s_formatter)
system_stream.setFormatter(system_formatter)

vault_logger.addHandler(vault_stream)
k8s_logger.addHandler(k8s_stream)
system_logger.addHandler(system_stream)

logging.basicConfig(level=logging.DEBUG, filename='/dev/null')