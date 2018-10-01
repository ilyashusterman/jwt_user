from datetime import datetime
from unittest import TestCase

from bunch import Bunch

from jwt_user import set_user_exclude_fields, get_jwt_user, \
	set_user_valid_fields, authorized_user, generate_request
from jwt_user.settings import DEFAULTS
from jwt_user.UserAuthorization import UserAuthorization


class TestUserAuthorization(TestCase):
	def setUp(self):
		self.jwt_user = UserAuthorization()
		self.payload = {
			'user_id': 'test',
			'username': 'test',
		}
		set_user_exclude_fields(set())
		self.token = self.jwt_user.generate_user_token(self.payload)
		self.user_values = {'username', 'user_id', 'token'}

	def generate_user_request(self, token=None):
		token = self.token if token is None else token
		request = generate_request(token)
		return request

	def test_header_valdiation(self):
		jwt_value = self.jwt_user.get_validated_token('{} {}'.format(
			DEFAULTS['JWT_AUTH_HEADER_PREFIX'],
			self.token))
		self.assertEqual(self.token, jwt_value)

	def test_decode_jwt(self):
		token_encoded = self.jwt_user.generate_user_token(self.payload)
		decoded = self.jwt_user.get_checked_decoded(jwt_value=token_encoded)
		self.assertEqual(decoded, self.payload)

	def test_decode_jwt_expired(self):
		self.payload['exp'] = datetime.utcnow() - DEFAULTS['JWT_EXPIRATION_DELTA']
		with self.assertRaises(Exception) as e:
			self.jwt_user.generate_user_token(self.payload)
			self.assertIn('Signature has expired', e)

	def test_decode_jwt_from_server(self):
		decoded = self.jwt_user.get_checked_decoded(jwt_value=self.token)
		self.assertEqual('test', decoded['username'])

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
		self.token = self.jwt_user.generate_user_token(self.payload)
		user_valid_fields = {'username', 'user_id', test_field, 'token'}
		set_user_valid_fields(user_valid_fields)
		user_request = self.generate_user_request(self.token)
		user = get_jwt_user(user_request)
		self.assertSetEqual(user_valid_fields, set(user.keys()))

	def test_decorator_authorize_user(self):
		_self = self

		class UserTest(object):

			def __init__(self):
				self.request =_self.generate_user_request()

			@authorized_user
			def authorize_test_user(self):
				return 'passed'

		user_test = UserTest()
		self.assertEqual(user_test.authorize_test_user(), 'passed')

	def test_decorator_non_authorize_user(self):
		"""should fail for python2 because of assertRaisesRegex"""
		_self = self

		class UserTest(object):

			def __init__(self):
				self.request =_self.generate_user_request(token='i am wrong')

			@authorized_user
			def authorize_test_user(self):
				return 'passed'

		user_test = UserTest()
		with self.assertRaisesRegex(Exception, 'Unauthorized user request'):
			user_test.authorize_test_user()
