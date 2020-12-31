import re


def validate_error_response(response, error_type, error_message_expression):
    """
    Validates that an error response from KMS is as expected.
    """

    if not isinstance(response, dict):
        print("Response is not a dictionary")
        return False

    if '__type' not in response:
        print("'__type' key is missing")
        return False

    if 'message' not in response:
        print("'message' key is missing")
        return False

    if error_type != response['__type']:
        print("The return type '%s' does not match the expected type '%s'" % (response['__type'], error_type))
        return False

    pattern = re.compile(error_message_expression)
    if not pattern.match(response['message']):
        print("The return message\n\t'%s'\ndoes not match the expected message pattern\n\t'%s'" % (response['message'], error_message_expression))
        return False

    return True
