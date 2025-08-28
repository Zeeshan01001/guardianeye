from setuptools import setup, find_packages
import os

# Ensure all necessary files are included
def package_files(directory):
    paths = []
    for (path, directories, filenames) in os.walk(directory):
        for filename in filenames:
            paths.append(os.path.join('..', path, filename))
    return paths

setup(
    name="guardianeye",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        'requests>=2.25.1',
        'yara-python>=4.2.0',
        'scikit-learn>=0.24.2',
        'watchdog>=2.1.6',
        'pefile>=2021.9.3',
        'typer>=0.9.0',       # Modern CLI framework
        'rich>=13.0.0',       # Rich terminal formatting
        'tabulate>=0.9.0',    # Table formatting
        'yaspin>=2.5.0',      # Terminal spinners
    ],
    entry_points={
        'console_scripts': [
            'guardianeye=guardianeye.cli.main:app',
            'ge=guardianeye.cli.main:app',  # Short command alias
        ],
    },
    package_data={
        'guardianeye': [
            'data/signatures/*.csv',
            'cli/*.py',
            'core/*.py',
        ] + package_files('guardianeye'),
    },
    include_package_data=True,
    zip_safe=False,  # Ensure the package is not installed as a zip
    author="zeeshan01001",
    author_email="your.email@example.com",
    description="GuardianEye - Advanced Malware Detection System",
    long_description=open('README.md').read(),
    long_description_content_type="text/markdown",
    url="https://github.com/zeeshan01001/GuardianEye",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Environment :: Console",
    ],
    python_requires='>=3.8',
) 