import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="drf_user",
    version=__import__('drf_user').__version__,
    author=__import__('drf_user').__author__,
    author_email="pypidev@civilmachines.com",
    description="User APP for Django REST Framework with API Views",
    long_description=long_description,
    long_description_content_type="text/markdown",
    license=__import__('drf_user').__license__,
    url="https://github.com/civilmachines/drf-user",
    python_requires=">=3.0",
    packages=setuptools.find_packages(),
    install_requires=open('requirements.txt').read().split(),
    include_package_data=True,
    classifiers=(
        'Development Status :: 5 - Production/Stable',
        'Environment :: Web Environment',
        'Framework :: Django',
        'Framework :: Django :: 1.11',
        'Framework :: Django :: 2.0',
        'Framework :: Django :: 2.1',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Topic :: Internet :: WWW/HTTP'
    ),
)
