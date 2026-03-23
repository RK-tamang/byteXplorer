from setuptools import setup, find_packages
import os

def get_version():
    return "1.0.0"

setup(
    name="bytexplorer-static",
    version="1.0.0",
    author="ByteXplorer",
    author_email="security@bytexplorer.com",
    description="Static Malware Analyzer - Analyze PE files without execution",
    long_description=open("README.md", "r", encoding="utf-8").read() if os.path.exists("README.md") else "",
    long_description_content_type="text/markdown",
    url="https://github.com/bytexplorer/static-malware-analyzer",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[
        "pefile>=2023.2.7",
        "python-magic>=0.4.27",
        "python-docx>=1.1.2",
        "reportlab>=4.2.2",
        "colorlog>=6.8.2",
    ],
    entry_points={
        "console_scripts": [
            "byteXplorerStatic = main:main",
        ],
    },
    python_requires=">=3.8",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Security :: Malware Analysis",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: POSIX :: Linux",
    ],
    include_package_data=True,
    zip_safe=False,
)
