from distutils.core import setup
# NOTICE!!
# This setup.py is written for py2exe
# Don't make a python package using this file!

try:
    import py2exe
except ImportError:
    pass

setup(name='shadowsocks',
        version='1.2.2',
        description='a lightweight tunnel proxy which can help you get through firewalls',
        author='clowwindy',
        author_email='clowwindy42@gmail.com',
        url='https://github.com/clowwindy/shadowsocks',
        options = {'py2exe': {'bundle_files': 1, 'compressed': True}},
        windows = [{"script":"local.py", "dest_base": "shadowsocks_local",}],
        zipfile = None)
