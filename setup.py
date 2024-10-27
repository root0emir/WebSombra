from setuptools import setup, find_packages

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name="websombramini",
    version="1.4",
    author="[root0emir]",
    description="Web analysis and reconnaissance tool for ethical hackers.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/root0emir/WebSombraMini", 
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'websombramini=websombramini:main',  
        ],
    },
 install_requires=[
    "requests>=2.20.0",
    "dnspython>=2.1.0",
    "whois>=0.9.13",
    "python-nmap>=0.6.1",  
    "beautifulsoup4>=4.6.0",
    "pyfiglet>=0.8.post1",
    "sublist3r>=1.0",
    "matplotlib>=3.3.0",
    "pandas>=1.1.0"
],

    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Intended Audience :: Developers",
        "Intended Audience :: Science/Research",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Internet",
    ],
    python_requires='>=3.6',
)
