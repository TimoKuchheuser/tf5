#!/usr/bin/env python3

import argparse
import sys

parser = argparse.ArgumentParser(description='nNGM Task Force 5 File Transfer')

if __name__ == '__main__':
    args = parser.parse_args(args=None if sys.argv[1:] else ['--help'])
