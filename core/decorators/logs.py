import logging
from core.exceptions.vault_k8s import VaultException
from core.helpers import template_log_record

def vault_log(func=None, *, msg=None, on_success=None, on_error=None, fatal=False, print_return=False,
                print_exception=False, no_error_text=False, warning=False, template_kvargs=False):
    def vault_info_log_decoratror(function):
        def wrapper(*args, **kvargs):
            vault_logger = logging.getLogger('__vault__')
            if warning:
                log_level = logging.WARNING
            else:
                log_level = logging.INFO
            if msg is not None:
                if template_kvargs:
                    vault_logger.log(log_level, template_log_record(msg, {**kvargs}))
                else:
                    vault_logger.log(log_level, msg)
            try:
                return_value = function(*args, **kvargs)
                if print_return:
                    vault_logger.log(log_level, return_value)
                if on_success is not None:
                    vault_logger.log(log_level, f'{on_success}')
                return return_value
            except VaultException as err:
                vault_logger.error(err.log_str(no_error_text=no_error_text))
                if on_error is not None:
                    vault_logger.error(on_error)
            except Exception as err:
                if on_error is not None:
                    vault_logger.error(on_error)
                if print_exception is True:
                    vault_logger.error(err)

            if fatal:
                exit(1)
            else:
                return False
        return wrapper
    if func:
        return vault_info_log_decoratror(func)
    else:
        return vault_info_log_decoratror