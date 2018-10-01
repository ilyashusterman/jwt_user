from jwt_user.settings import DEFAULTS


class Request(object):

	def __init__(self):
		self.headers = {}

	def set_authorize_token(self, token):
		token_header = '{} {}'.format(DEFAULTS['JWT_AUTH_HEADER_PREFIX'], token)
		self.headers[DEFAULTS['JWT_AUTH_HEADER']] = token_header