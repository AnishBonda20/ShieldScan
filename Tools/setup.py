from setuptools import setup, find_packages

setup(
    name="rootkit_scanner",
    version="0.2.0",
    py_modules=[
        "main",
        "config",
        "rootkit_detector",
        "process_analyzer",
        "driver_scanner",
        "network_scanner",
        "registry_scanner",
        "volatility_analyzer",
        "memory_capture",
        "rootkitscanner",
    ],
    install_requires=[
        "psutil>=5.9",
        "pywin32>=306",
    ],
    extras_require={
        "yara": ["yara-python>=4.3"],
    },
    python_requires=">=3.10",
    entry_points={
        "console_scripts": [
            "rootkit-scan=main:main",
        ],
    },
)
