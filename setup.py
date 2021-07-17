import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="drf_user",
    version=__import__("drf_user").__version__,
    author=__import__("drf_user").__author__,
    author_email="me@himanshus.com",
    maintainer="Sumit Singh",
    maintainer_email="sumit.singh4613@gmail.com",
    description="User APP for Django REST Framework with API Views",
    long_description=long_description,
    long_description_content_type="text/markdown",
    license=__import__("drf_user").__license__,
    url="https://github.com/101loop/drf-user",
    python_requires=">=3.6",
    packages=setuptools.find_packages(),
    install_requires=open("requirements.txt").read().split(),
    include_package_data=True,
    classifiers=(
        "Development Status :: 5 - Production/Stable",
        "Environment :: Web Environment",
        "Framework :: Django",
        "Framework :: Django :: 2.2",
        "Framework :: Django :: 3.1",
        "Framework :: Django :: 3.2",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Topic :: Software Development :: Libraries",
        "Topic :: Internet :: WWW/HTTP",
    ),
)
