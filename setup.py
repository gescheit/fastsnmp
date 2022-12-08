#!/usr/bin/python3
__version__ = '0.13'

from setuptools import setup, Extension

classifiers = [
    'Development Status :: 4 - Beta',
    'Operating System :: POSIX :: Linux',
    'License :: OSI Approved :: MIT License',
    'Programming Language :: Python :: 3 :: Only',
    'Topic :: System :: Networking :: Monitoring',
]
cmdclass = {}

try:
    from Cython.Distutils import build_ext
except ImportError:
    USE_CYTHON = False
else:
    USE_CYTHON = True
    cmdclass.update({'build_ext': build_ext})

ext = '.pyx' if USE_CYTHON else '.c'
extensions = [Extension("fastsnmp.snmp_parser", ["fastsnmp/snmp_parser" + ext])]

if __name__ == "__main__":
    if USE_CYTHON:
        from Cython.Build import cythonize

        extensions = cythonize(extensions, compiler_directives={"cdivision": True})
    setup(name='fastsnmp',
          ext_modules=extensions,
          version=__version__,
          author="Aleksandr Balezin",
          packages=['fastsnmp'],
          package_data={'lib': ['*.pyx', '*.c', 'README.md', 'examples/*.py']},
          license='MIT',
          url='https://github.com/gescheit/fastsnmp',
          author_email='gescheit12@gmail.com',
          classifiers=classifiers,
          platforms=['Linux'],
          long_description=open('README.md', 'r').read(),
          long_description_content_type='text/markdown',
          keywords="SNMP poller parser library coder decoder",
          description="SNMP poller oriented to poll bunch of hosts in short time. "
                      "Package include poller and SNMP library",
          requires=["Cython"],
          )
