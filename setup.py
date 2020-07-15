from setuptools import setup

with open("README.md", 'r') as file:
    long_description=file.read()

setup(
        name='sendit',
        version='1.0.3',
        author='Matt Baker',
        author_email="mbakervtech@gmail.com",
        description="A package that provides easy access to forming and sending custom messages from Layer 2 to Layer 4",
        long_description=long_description,
        long_description_content_type="text/markdown",
        url="https://github.com/mbaker-97/networkingpy",
        packages=['sendit', 'sendit/applications', 'sendit/protocols', 'sendit/handlers', 'sendit/helper_functions'],
        include_package_data=True,

        )
