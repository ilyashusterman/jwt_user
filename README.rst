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
    >>> 

Documentation
-------------

View the full docs online at https://jwt_user.readthedocs.io/en/latest/


Tests
-----

You can run tests from the project root after cloning with:

    $ make smoke