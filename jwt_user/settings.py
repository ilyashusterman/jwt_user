import os
import uuid
from datetime import timedelta

DEFAULTS = {
	'JWT_PRIVATE_KEY': os.environ.get('JWT_PRIVATE_KEY', uuid.uuid4().hex),
	'JWT_SECRET_KEY': os.environ.get('JWT_SECRET_KEY', uuid.uuid4().hex),
	'JWT_ALGORITHM': 'HS256',
	'JWT_VERIFY': True,
	'JWT_VERIFY_EXPIRATION': True,
	'JWT_LEEWAY': 0,
	'JWT_EXPIRATION_DELTA': timedelta(seconds=int(os.environ.get('JWT_EXPIRATION_DELTA', 3600))),
	'JWT_AUDIENCE': None,
	'JWT_ISSUER': None,
	'JWT_ALLOW_REFRESH': False,
	'JWT_REFRESH_EXPIRATION_DELTA': timedelta(days=7),
	'JWT_AUTH_HEADER_PREFIX': os.environ.get('JWT_AUTH_HEADER_PREFIX', 'JWT'),
	'JWT_AUTH_HEADER': os.environ.get('JWT_AUTH_HEADER', 'Authorization')
}

VALID_USER_FIELDS = {'username', 'user_id'}
EXCLUDE_USER_FIELDS = set()