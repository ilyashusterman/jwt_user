from functools import wraps

from jwt_user.Request import Request
from jwt_user.UserAuthorization import UserAuthorization

USER_AUTHORIZATION_INSTANCE = None


def get_user_authorization():
	global USER_AUTHORIZATION_INSTANCE
	USER_AUTHORIZATION_INSTANCE = USER_AUTHORIZATION_INSTANCE or UserAuthorization()
	return USER_AUTHORIZATION_INSTANCE


def authorize_token_from_request(request):
	user = None
	user_jwt = get_user_authorization().authorize(request)
	user = set_user_if_valid(user, user_jwt)
	return user


def authorize_token_from_headers(headers):
	user = None
	user_jwt = get_user_authorization().authorize_headers(headers)
	user = set_user_if_valid(user, user_jwt)
	return user


def set_user_if_valid(user, user_jwt):
	if user_jwt is not None:
		user = user_jwt[0]
		user.token = user_jwt[1]
	return user


def get_jwt_user(request):
	user = authorize_token_from_request(request)
	if user is None:
		raise Exception('Unauthorized token request')
	return user


def get_jwt_user_headers(headers):
	user = authorize_token_from_headers(headers)
	if user is None:
		raise Exception('Unauthorized token request')
	return user


def set_user_valid_fields(valid_user_fields):
	get_user_authorization().default_user_valid_fields = valid_user_fields


def set_user_exclude_fields(exclude_fields):
	get_user_authorization().exclude_fields = exclude_fields


def authorized_user(f):
	@wraps(f)
	def check_user(*args, **kwds):
		request = args[0].request
		try:
			user = authorize_token_from_request(request)
		except:
			user = None
		if user is not None:
			return f(*args, **kwds)
		else:
			raise Exception('Unauthorized user request {}'.format(request.headers))
	return check_user


def generate_token(payload):
	return get_user_authorization().generate_user_token(payload)


def decode_token(token):
	return get_user_authorization().get_checked_decoded(token)


def generate_request(token):
	request = Request()
	request.set_authorize_token(token)
	return request