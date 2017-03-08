from setuptools import setup, find_packages

setup(
    name="aws-dbg-saml",
    version="0.1",
    packages=find_packages(),
    install_requires=['requests', 'boto3', 'botocore', 'bs4'],
    entry_points={
        'console_scripts': [
            'dbg_aws_saml = dbg_aws_saml.dbg_aws_saml:main'
        ]
    }
)