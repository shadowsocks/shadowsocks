from setuptools import setup, find_packages

setup(
    name = "shadowsocks",
    version = "1.3.0",
    license = 'MIT',
    description = "a lightweight tunnel proxy",
    author = 'clowwindy42@gmail.com',
    url = 'https://github.com/clowwindy/shadowsocks',
    packages = ['shadowsocks'],
    package_data={
        'shadowsocks': ['README.md', 'LICENSE', 'config.json']
    },
    install_requires = ['setuptools',
                        ],
    entry_points="""
    [console_scripts]
    sslocal = shadowsocks.local:main
    ssserver = shadowsocks.server:main
    """,
)
