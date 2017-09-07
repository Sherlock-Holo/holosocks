from setuptools import setup, find_packages

setup(
    name='Holosocks',
    version='0.1',
    author='Sherlock Holo',
    author_email='sherlockya@gmail.com',
    license='BSD',
    keywords='proxy',
    url='https://github.com/Sherlock-Holo/holosocks',
    zip_safe=True,

    packages=find_packages(),
    install_requires=[
        'setuptools',
        'pycryptodomex'
    ],
    extras_require={
        'uvloop': []
    },
    entry_points={
        'console_scripts': [
            'sslocal = holosocks.sslocal:main',
            'ssserver = holosocks.sserver:main'
        ]
    },

    classifiers=[
        'Environment :: Console',
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6'
    ]
)
