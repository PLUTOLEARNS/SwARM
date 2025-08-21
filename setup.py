from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="swarm-ids",
    version="1.0.0",
    author="SwARM Development Team",
    description="Swarm Agent Response Monitoring - Distributed Intrusion Detection System",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=6.2.0",
            "pytest-cov>=2.12.0",
            "pytest-asyncio>=0.15.0",
            "black>=21.6.0",
            "flake8>=3.9.0",
            "mypy>=0.910",
            "coverage>=5.5",
        ],
    },
    entry_points={
        "console_scripts": [
            "swarm-ids=src.main:main",
        ],
    },
)
