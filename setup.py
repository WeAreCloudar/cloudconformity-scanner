from setuptools import setup


def get_version():
    with open('version.txt', 'r') as fh:
        return fh.read().strip()


setup(
    name='cloudconformity-scanner',
    version=get_version(),
    description="Run the CloudConformity Template Scanner from the commandline",
    author='Ben Bridts',
    author_email='ben@cloudar.be',
    url='',  # todo
    packages=['cloudconformity_scanner'],
    entry_points={
        'console_scripts': [
            'cloudconformity-scanner = cloudconformity_scanner.cli:main',
        ]
    },
    install_requires=[
        'requests',
        'ruamel.yaml'
    ],
)
