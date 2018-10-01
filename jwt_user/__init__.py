from functools import wraps

from jwt_user.Request import Request
from jwt_user.UserAuthorization import UserAuthorization


def authorize_token_from_request(request):
	user = None
	user_jwt = UserAuthorization().authorize(request)
	if user_jwt is not None:
		user = user_jwt[0]
		user.token = user_jwt[1]

	return user


def get_jwt_user(request):
	user = authorize_token_from_request(request)
	if user is None:
		raise Exception('Unauthorized token request')
	return user


def set_user_valid_fields(valid_user_fields):
	UserAuthorization.valid_user_fields = valid_user_fields


def set_user_exclude_fields(exclude_fields):
	UserAuthorization.exclude_fields = exclude_fields


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
	return UserAuthorization().generate_user_token(payload)


def decode_token(token):
	return UserAuthorization().get_checked_decoded(token)


def generate_request(token):
	request = Request()
	request.set_authorize_token(token)
	return request