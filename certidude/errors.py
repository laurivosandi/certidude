
class RequestExists(Exception):
    pass

class FatalError(Exception):
    """
    Exception to be raised when user intervention is required
    """
    pass

class DuplicateCommonNameError(FatalError):
    pass
