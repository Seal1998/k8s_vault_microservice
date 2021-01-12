import logging
import traceback
import re
from core.exceptions.vault_k8s import VaultException

class Log:

    def __init__(self, logger_name, exception_handler=None):
        self.logger = logging.getLogger(logger_name)
        self.exception_handler = exception_handler

    @classmethod
    def create_vault_logger(cls):
        vault_logger = cls('__vault__')
        vault_logger.exception_handler = vault_logger.__vault_exception_handler
        return vault_logger

    @classmethod
    def create_k8s_logger(cls):
        k8s_logger = cls('__k8s__')
        k8s_logger.exception_handler = k8s_logger.__k8s_exception_handler
        return k8s_logger

    def __k8s_exception_handler(self, exception):
        self.log_msg(logging.ERROR, exception)

    def __vault_exception_handler(self, exception):
        if type(exception) is VaultException:
            self.log_msg(logging.ERROR, exception.log_str())
        else:
            self.log_msg(logging.ERROR, exception)

    def log_msg(self, log_level=logging.INFO, msg=None):
        self.logger.log(log_level, msg)

    def log_event(self, *, event, event_args, event_kvargs, log_level=None, msg=None, on_success=None, on_error=None, 
                fatal=False, print_return=False, print_exception=False, template_kvargs=False):
        if msg:
            if template_kvargs:
                msg = self.template_log_record(msg, event_kvargs)
            self.log_msg(log_level, msg)
        try:
            return_value = event(*event_args, **event_kvargs)
            if print_return:
                self.log_msg(log_level, str(return_value))
            if on_success:
                self.log_msg(log_level, on_success)
            return return_value
        except Exception as ex:
            self.exception_handler(ex)
            if on_error:
                if template_kvargs:
                    on_error = self.template_log_record(on_error, event_kvargs)
                self.log_msg(logging.ERROR, on_error)
            if print_exception:
                print(type(ex), traceback.format_exc())
            if fatal:
                exit(1)
            else:
                return False #Failed function return false

    def warning(self, func=None, **log_kvargs):
        def warning_decorator(function):
            def wrapper(*args, **kvargs):
                log_kvargs['log_level'] = logging.WARNING
                return self.log_event(event=function, event_args=args, event_kvargs=kvargs, **log_kvargs)
            return wrapper
        if func:
            return warning_decorator(func)
        else:
            return warning_decorator

    def info(self, func=None, **log_kvargs):
        def info_decorator(function):
            def wrapper(*args, **kvargs):
                log_kvargs['log_level'] = logging.INFO
                return self.log_event(event=function, event_args=args, event_kvargs=kvargs, **log_kvargs)
            return wrapper
        if func:
            return info_decorator(func)
        else:
            return info_decorator

    def template_log_record(self, template_string, values_dict): #proccessing [[secret_name]] secret
        capture_keys_regexp = r'(?<=\[\[)[\w]+(?=\]\])'
        capture_template_pattern_regexp = r'\[\[[\w]+\]\]'

        string_els = {index: word for index,word in enumerate(template_string.split(' '))}
        keys_els = {index: re.search(capture_keys_regexp, word) for index,word in string_els.items() 
                                                                if re.search(capture_keys_regexp, word)}

        list(map(string_els.pop, keys_els.keys()))
        
        template_keys_templated = {index: re.sub(capture_template_pattern_regexp, str(values_dict[template_key.group()]), template_key.string) 
                                                        for index,template_key in keys_els.items()}
        
        templated_string_els = {index: value for index,value in sorted({**string_els, **template_keys_templated}.items())}
        return ' '.join(templated_string_els.values())