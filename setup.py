from setuptools import find_packages, setup

with open("requirements.in") as f:
    install_requires = [line for line in f if line and line[0] not in "#-"]

with open("test-requirements.in") as f:
    tests_require = [line for line in f if line and line[0] not in "#-"]

setup(
    name="requests-iap2",
    version="1.0.0",
    url="https://github.com/climateengine/requests-iap2",
    author="Bennett Kanuka",
    author_email="jan.masarik@kiwi.com",
    packages=find_packages(),
    install_requires=install_requires,
    tests_require=tests_require,
    include_package_data=True,
    classifiers=[
        "Environment :: Console",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
    ],
)
