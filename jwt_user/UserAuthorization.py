from datetime import datetime

import jwt
from bunch import Bunch

from jwt_user.settings import DEFAULTS, VALID_USER_FIELDS, EXCLUDE_USER_FIELDS


class UserJSONWebTokenAuthorization(object):

	valid_user_fields = VALID_USER_FIELDS
	exclude_fields = EXCLUDE_USER_FIELDS

	def __init__(self):
		self.options = {
			'exp':  datetime.utcnow() + DEFAULTS['JWT_EXPIRATION_DELTA'],
		}

	def get_header_prefix(self):
		return '{} '.format(DEFAULTS['JWT_AUTH_HEADER_PREFIX'])

	def decode_user_token(self, token):
		secret_key = DEFAULTS['JWT_SECRET_KEY']
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

	def generate_user_token(self, user_payload):
		secret_key = DEFAULTS['JWT_SECRET_KEY']
		user_payload.update(self.options)
		return jwt.encode(
			user_payload,
			secret_key,
			DEFAULTS['JWT_ALGORITHM'],
		).decode('utf-8')

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

	def get_jwt_value(self, request):
		return self.get_validated_token(request.headers[DEFAULTS['JWT_AUTH_HEADER']])

	def get_checked_decoded(self, jwt_value):
		try:
			decoded = self.decode_user_token(jwt_value)
			return decoded
		except jwt.ExpiredSignature:
			msg = 'Signature has expired.'
			raise Exception(msg)
		except jwt.DecodeError as e:
			msg = 'Error decoding signature.'
			raise Exception(msg)
		except jwt.InvalidTokenError:
			raise Exception()

	def get_user_valid_fields(self):
		return self.valid_user_fields.union(self.options.keys()).union(set('token'))

	def authorize(self, request):
		jwt_value = self.get_jwt_value(request)
		if jwt_value is None:
			return None
		jwt_decoded_payload = self.get_checked_decoded(jwt_value)
		user_valid_fields = self.get_user_valid_fields()
		if not set(jwt_decoded_payload.keys()).issubset(user_valid_fields):
			msg = 'Invalid user attributes {}'.format(
				set(jwt_decoded_payload.keys())-self.valid_user_fields)
			raise Exception(msg)
		user = self.get_user_from_payload(jwt_decoded_payload)
		return user, jwt_value

	def get_user_from_payload(self, user_decoded_payload):
		exclude_fields = self.exclude_fields.union(self.options.keys())
		exclude_user_fields = list(
			filter(user_decoded_payload.__contains__, exclude_fields))
		list(map(user_decoded_payload.__delitem__, exclude_user_fields))
		return Bunch(user_decoded_payload)

