from datetime import datetime
from unittest import TestCase, skip

from bunch import Bunch

from settings import DEFAULTS
from user_authorization import UserJSONWebTokenAuthentication, get_jwt_user, \
	set_user_exclude_fields, set_user_valid_fields


class TestUserJSONWebTokenAuthentication(TestCase):
	def setUp(self):
		self.validator = UserJSONWebTokenAuthentication()
		self.payload = {
			'user_id': 'test',
			'username': 'test',
		}
		set_user_exclude_fields(set())
		self.token = self.validator.generate_user_token(self.payload)
		self.user_values = {'username', 'user_id', 'token'}

	def generate_user_request(self, token=None):
		token = self.token if token is None else token
		request = Bunch()
		request.headers = {
			DEFAULTS['JWT_AUTH_HEADER']: 'JWT {}'.format(token)}
		return request

	def test_header_valdiation(self):
		jwt_value = self.validator.get_validated_token('{} {}'.format(
			DEFAULTS['JWT_AUTH_HEADER_PREFIX'],
			self.token))
		self.assertEqual(self.token, jwt_value)

	def test_decode_jwt(self):
		token_encoded = self.validator.generate_user_token(self.payload)
		decoded = self.validator.get_checked_decoded(jwt_value=token_encoded)
		self.assertEqual(decoded, self.payload)

	def test_decode_jwt_expired(self):
		self.payload['exp'] = datetime.utcnow() - DEFAULTS['JWT_EXPIRATION_DELTA']
		with self.assertRaises(Exception) as e:
			self.validator.generate_user_token(self.payload)
			self.assertIn('Signature has expired', e)

	@skip('due to token expire could not run this')
	def test_decode_jwt_from_server(self):
		decoded = self.validator.get_checked_decoded(jwt_value=self.token)
		self.assertEqual('test@email.com', decoded['username'])

	def test_request_jwt_user_authenticate(self):
		request = self.generate_user_request()
		user = get_jwt_user(request)
		self.assertSetEqual(set(user.keys()), self.user_values, msg=user.keys())

	def test_change_user_exclude_fields(self):
		request = self.generate_user_request()
		set_user_exclude_fields({'username'})
		user = get_jwt_user(request)
		self.assertNotIn('username', user.keys())

	def test_change_user_valid_fields(self):
		test_field = 'test_field'
		self.payload.update({
			test_field: 'test'
		})
		self.token = self.validator.generate_user_token(self.payload)
		user_valid_fields = {'username', 'user_id', test_field, 'token'}
		set_user_valid_fields(user_valid_fields)
		user_request = self.generate_user_request(self.token)
		user = get_jwt_user(user_request)
		self.assertSetEqual(user_valid_fields, set(user.keys()))