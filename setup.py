#!/usr/bin/python3
__version__ = '0.1'
from distutils.core import setup
from distutils.extension import Extension
from Cython.Distutils import build_ext

classifiers = [
    'Development Status :: 4 - Beta',
    'Environment :: Console',
    'Operating System :: POSIX :: Linux',
    'License :: OSI Approved :: GNU General Public License v2 (GPLv2)',
    'Programming Language :: Python :: 3 :: Only',
    'Topic :: System :: Networking :: Monitoring',
],

cmdclass = {}

try:
    from Cython.Distutils import build_ext
except ImportError:
    USE_CYTHON = False
else:
    USE_CYTHON = True
    cmdclass.update({'build_ext': build_ext})

ext = '.pyx' if USE_CYTHON else '.c'
extensions = [Extension("fastsnmp/snmp_parser", ["fastsnmp/snmp_parser" + ext])]

if __name__ == "__main__":
    if USE_CYTHON:
        from Cython.Build import cythonize
        extensions = cythonize(extensions)

    setup(name='fastsnmp',
          ext_modules=extensions,
          version=__version__,
          author="Aleksandr Balezin",
          packages=['fastsnmp'],
          license='LICENSE',
          url='https://github.com/gescheit/fastsnmp',
          author_email='gescheit12@gmail.com',
          classifiers=classifiers,
          platforms=['Linux'],
          )
