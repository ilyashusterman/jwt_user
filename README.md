jwt_user
=====

A Python implementation of acquiring, authorizing user from jwt token.
designed to work for any request entity from flask,django,tornado frameworks. 

Installing
----------

Install with **pip**:

    $ pip install jwt_user


Usage
-----

    >>> import jwt_user
    >>> payload = {'username': 'test'}
    >>> token = jwt_user.generate_token(payload)
    >>> request = jwt_user.generate_request(token)
    >>> user = jwt_user.get_jwt_user(request)
    >>> user
    {}
    >>> user.username
    'test'
    >>> #Second usage
    ... 
    >>> import tornado
    >>> BaseRequestHandler = tornado.web.RequestHandler
    >>> class MainHandler(BaseRequestHandler):
    ...     @jwt_user.authorized_user
    ...     def get(self):
    ...         self.write('Hello, Authorized user')
    ...
    >>> class MainUserHandler(BaseRequestHandler):
    ...     @jwt_user.authorized_user
    ...     def get(self):
    ...         user = jwt_user.get_jwt_user(self.request)
    ...         self.write('Hello, {}'.format(user.username))
    >>>
    >>> def make_app():
    ...     user_valid_fields = {'username', 'user_id', 'token'}
	...     jwt_user.set_user_valid_fields(user_valid_fields)
	...     application = tornado.web.Application([
    ...     (r'/', MainHandler),
    ...     (r'/user_page', MainUserHandler)])
    ...     return application
    >>>
],
        
Documentation
-------------

View the full docs online at https://jwt_user.readthedocs.io/en/latest/


Tests
-----

You can run tests from the project root after cloning with:

    $ make smoke