
from setuptools import setup

setup(
    name='rfc6266',
    version='0.0.1',  # symver
    py_modules=['rfc6266', 'test_rfc6266'],
    install_requires=['LEPL'],
    use_2to3=True,
)

