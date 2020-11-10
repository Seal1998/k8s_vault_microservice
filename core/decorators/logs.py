from core.exceptions.vault_k8s import VaultException
import logging

def vault_log(function=None, *, msg=None, on_success=None, on_error=None, fatal=False, 
                print_return=False, print_exception=False, no_text=False, warning = False):
    def vault_info_log_decoratror(function):
        def wrapper(*args, **kvargs):
            vault_logger = logging.getLogger('__vault__')
            cobj = args[0]
            if warning:
                log_level = logging.WARNING
            else:
                log_level = logging.INFO
            #vault_logger.log(log_level, 'test')
            try:
                if msg is not None:
                    vault_logger.log(log_level, msg)
                return_value = function(*args, **kvargs)
                if on_success is not None:
                    vault_logger.log(log_level, f'{msg} {on_success}')
                if print_return is True:
                    vault_logger.log(log_level, return_value)
                return return_value
            except VaultException as err:
                vault_logger.error(err.log_str(no_text=no_text))
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
    if function:
        return vault_info_log_decoratror(function)
    return vault_info_log_decoratror