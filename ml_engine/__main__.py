"""允许通过 python -m ml_engine 调用 ML CLI"""
import sys

from .cli import main

if __name__ == '__main__':
    sys.exit(main())
