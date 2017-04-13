
import logging

logger = logging.getLogger("api")

def whitelist_subnets(subnets):
    """
    Validate source IP address of API call against subnet list
    """
    import falcon

    def wrapper(func):
        def wrapped(self, req, resp, *args, **kwargs):
            # Check for administration subnet whitelist
            for subnet in subnets:
                if req.context.get("remote_addr") in subnet:
                    break
            else:
                logger.info(u"Rejected access to administrative call %s by %s from %s, source address not whitelisted",
                    req.env["PATH_INFO"],
                    req.context.get("user", "unauthenticated user"),
                    req.context.get("remote_addr"))
                raise falcon.HTTPForbidden("Forbidden", "Remote address %s not whitelisted" % remote_addr)

            return func(self, req, resp, *args, **kwargs)
        return wrapped
    return wrapper

def whitelist_content_types(*content_types):
    import falcon

    def wrapper(func):
        def wrapped(self, req, resp, *args, **kwargs):
            for content_type in content_types:
                if req.get_header("Content-Type") == content_type:
                    return func(self, req, resp, *args, **kwargs)
            raise falcon.HTTPUnsupportedMediaType(
                "This API call accepts only %s content type" % ", ".join(content_types))
        return wrapped
    return wrapper

