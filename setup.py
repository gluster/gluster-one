from setuptools import setup


name = 'gluster-colonizer'

setup(
    name=name,
    version='1.0.4',
    description='Gluster colonizer is node executor for quick deployments',
    license='GPLv3',
    author='Dustin Black',
    author_email='dblack@redhat.com',
    url='https://github.com/gluster/gluster-colonizer',
    packages=['gluster-colonizer'],
    package_dir={'gluster-colonizer':''},
    classifiers=[
        'Development Status :: 4 - Beta'
        'Environment :: Console'
        'Intended Audience :: System Administrators'
        'License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)'
        'Operating System :: POSIX :: Linux'
        'Programming Language :: Python'
        'Topic :: System :: Filesystems'
    ],
    install_requires=[
        'python-zeroconf',
        'python-xmltodict',
        'ansible>=2.5.2',
    ],
)
