from datetime import datetime
import jwt
from bunch import Bunch

from settings import DEFAULTS, VALID_USER_FIELDS, EXCLUDE_USER_FIELDS


class UserJSONWebTokenAuthentication(object):

	def __init__(self):
		self.options = {
			'exp':  datetime.utcnow() + DEFAULTS['JWT_EXPIRATION_DELTA'],
		}
		self.valid_user_fields = VALID_USER_FIELDS
		self.exclude_fields = EXCLUDE_USER_FIELDS

	def get_validated_token(self, header_value):
		header_prefix = self.get_header_prefix()
		auth = header_value.split(header_prefix)
		if len(auth) == 1:
			msg = 'Invalid Authorization header. No credentials provided.'
			raise Exception(msg)
		elif len(auth) > 2:
			msg = 'Invalid Authorization header. Credentials string should ' \
			      'not contain spaces.'
			raise Exception(msg)
		return auth[1]

	def get_header_prefix(self):
		return '{} '.format(DEFAULTS['JWT_AUTH_HEADER_PREFIX'])

	def get_jwt_value(self, request):
		return self.get_validated_token(request.headers[DEFAULTS['JWT_AUTH_HEADER']])

	def authenticate(self, request):
		jwt_value = self.get_jwt_value(request)
		if jwt_value is None:
			return None
		jwt_decoded_payload = self.get_checked_decoded(jwt_value)
		if not self.valid_user_fields.issubset(jwt_decoded_payload.keys()):
			msg = 'Invalid user attributes {}'.format(
				set(jwt_decoded_payload.keys())-self.valid_user_fields)
			raise Exception(msg)
		user = self.get_user_from_payload(jwt_decoded_payload)
		return user, jwt_value

	def jwt_decode_payload(self, token):
		secret_key = DEFAULTS['JWT_SECRET_KEY']
		print('token={}'.format(token))
		return jwt.decode(
			token,
			None or secret_key,
			DEFAULTS['JWT_VERIFY'],
			options=self.options,
			leeway=DEFAULTS['JWT_LEEWAY'],
			audience=DEFAULTS['JWT_AUDIENCE'],
			issuer=DEFAULTS['JWT_ISSUER'],
			algorithms=[DEFAULTS['JWT_ALGORITHM']]
		)

	def jwt_encode_payload(self, payload):
		secret_key = DEFAULTS['JWT_SECRET_KEY']
		payload.update(self.options)
		return jwt.encode(
			payload,
			secret_key,
			DEFAULTS['JWT_ALGORITHM'],
		).decode('utf-8')

	def get_checked_decoded(self, jwt_value):
		try:
			decoded = self.jwt_decode_payload(jwt_value)
			return decoded
		except jwt.ExpiredSignature:
			msg = 'Signature has expired.'
			raise Exception(msg)
		except jwt.DecodeError as e:
			msg = 'Error decoding signature.'
			raise Exception(msg)
		except jwt.InvalidTokenError:
			raise Exception()

	def get_user_from_payload(self, user_decoded_payload):
		map(user_decoded_payload.__delitem__,
			filter(user_decoded_payload.__contains__, self.exclude_fields))
		return Bunch(user_decoded_payload)


def authorize_token_from_request(request):
	user = None
	user_jwt = UserJSONWebTokenAuthentication().authenticate(request)
	if user_jwt is not None:
		user = user_jwt[0]
		user.token = user_jwt[1]

	return user


def get_jwt_user(request):
	user = authorize_token_from_request(request)
	if user is None:
		raise Exception('Unauthorized token request')
	return user
