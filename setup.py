import os
import ast
from setuptools import setup


PACKAGE_NAME = 'moses'


def load_description(fname):
    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, fname)) as f:
        return f.read().strip()


def get_version(fname):
    with open(fname) as f:
        source = f.read()
    module = ast.parse(source)
    for e in module.body:
        if isinstance(e, ast.Assign) and \
                len(e.targets) == 1 and \
                e.targets[0].id == '__version__' and \
                isinstance(e.value, ast.Str):
            return e.value.s
    raise RuntimeError('__version__ not found')


setup(
    name=PACKAGE_NAME,
    packages=['moses', 'moses.staff', 'moses.tests'],
    version=get_version('{}/version.py'.format(PACKAGE_NAME)),
    description='TLS encrypted socks5 proxy',
    long_description=load_description('README.rst'),
    classifiers=[
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.4',
    ],
    keywords=['socks', 'proxy'],
    author='Kay Zheng',
    author_email='l04m33@gmail.com',
    url='https://github.com/l04m33/moses',
    license='MIT',
    zip_safe=False,
    install_requires=[],
    extras_require={
        'dev': ['nose', 'coverage']
    },
    entry_points='''
    [console_scripts]
    moses = moses.cmd:main
    staff = moses.staff.cmd:main
    '''
)
