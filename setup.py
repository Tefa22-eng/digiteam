# setup.py
from setuptools import setup, find_packages

setup(
    name="digiteam",
    version="2.0.0",
    description="DIGI TEAM - Elite Reconnaissance Framework",
    author="DIGI TEAM",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[
        "rich>=13.0.0",
        "pyyaml>=6.0",
        "requests>=2.31.0",
        "python-whois>=0.8.0",
        "dnspython>=2.4.0",
        "urllib3>=2.0.0",
    ],
    entry_points={
        "console_scripts": [
            "digiteam=main:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
    ],
)