from setuptools import setup, find_packages
from os import path

from io import open

here = path.abspath(path.dirname(__file__))

with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='jwt_user',
    version='0.0.4',
    description='Authorize user via jwt',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/ilyashusterman/jwt_user',
    author='Ilya shusterman',
    author_email='shusterilyaman@gmail.com',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Topic :: Software Development',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
    ],
    keywords='sample setuptools development',
    packages=find_packages(exclude=['tests']),
    install_requires=['PyJWT', 'bunch', 'six'],
    project_urls={
        'Bug Reports': 'https://github.com/ilyashusterman/jwt_user/issues',
        'Funding': 'https://donate.pypi.org',
        'Source': 'https://github.com/ilyashusterman/jwt_user/',
    },
)