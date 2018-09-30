from functools import wraps

from jwt_user.UserAuthorization import UserJSONWebTokenAuthorization


def authorize_token_from_request(request):
	user = None
	user_jwt = UserJSONWebTokenAuthorization().authorize(request)
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
	UserJSONWebTokenAuthorization.valid_user_fields = valid_user_fields


def set_user_exclude_fields(exclude_fields):
	UserJSONWebTokenAuthorization.exclude_fields = exclude_fields


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
			request = list(request)
			raise Exception('Unauthorized user request {}'.format(request))
	return check_user