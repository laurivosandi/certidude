
def expand_paths():
    """
    Prefix '..._path' keyword arguments of target function with 'directory' keyword argument
    and create the directory if necessary

    TODO: Move to separate file
    """
    def wrapper(func):
        def wrapped(**arguments):
            d = arguments.get("directory")
            for key, value in arguments.items():
                if key.endswith("_path"):
                    if d:
                        value = os.path.join(d, value)
                    value = os.path.realpath(value)
                    parent = os.path.dirname(value)
                    if not os.path.exists(parent):
                        click.echo("Making directory %s for %s" % (repr(parent), repr(key)))
                        os.makedirs(parent)
                    elif not os.path.isdir(parent):
                        raise Exception("Path %s is not directory!" % parent)
                    arguments[key] = value
            return func(**arguments)
        return wrapped
    return wrapper

