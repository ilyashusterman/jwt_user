from datetime import datetime
from unittest import TestCase, skip

from bunch import Bunch

from settings import DEFAULTS
from user_authorization import UserJSONWebTokenAuthentication


class TestUserJSONWebTokenAuthentication(TestCase):
	def setUp(self):
		self.validator = UserJSONWebTokenAuthentication()
		self.payload = {
			'user_id': 'test',
			'username': 'test',
			# 'email': 'test@email.com'
		}
		self.token = self.validator.jwt_encode_payload(self.payload)
		self.user_values = {'username', 'user_id', 'exp'}


	def test_header_valdiation(self):
		jwt_value = self.validator.get_validated_token('{} {}'.format(
			DEFAULTS['JWT_AUTH_HEADER_PREFIX'],
			self.token))
		self.assertEqual(self.token, jwt_value)

	def test_decode_jwt(self):
		token_encoded = self.validator.jwt_encode_payload(self.payload)
		decoded = self.validator.get_checked_decoded(jwt_value=token_encoded)
		self.assertEqual(decoded, self.payload)

	def test_decode_jwt_expired(self):
		self.payload['exp'] = datetime.utcnow() - DEFAULTS['JWT_EXPIRATION_DELTA']
		with self.assertRaises(Exception) as e:
			self.validator.jwt_encode_payload(self.payload)
			self.assertIn('Signature has expired', e)

	@skip('due to token expire could not run this')
	def test_decode_jwt_from_server(self):
		decoded = self.validator.get_checked_decoded(jwt_value=self.token)
		self.assertEqual('test@email.com', decoded['username'])

	def test_request_jwt_user_authenticate(self):
		request = Bunch()
		token_encoded = self.validator.jwt_encode_payload(self.payload)
		request.headers = {DEFAULTS['JWT_AUTH_HEADER']: 'JWT {}'.format(token_encoded)}
		user = UserJSONWebTokenAuthentication().authenticate(request)[0]
		self.assertSetEqual(set(user.keys()), self.user_values)