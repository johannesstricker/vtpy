#!/usr/bin/env python3
import argparse
import pprint
import vtpy


parser = argparse.ArgumentParser(description='Upload a file to virustotal.com and have it analyzed.')
parser.add_argument('--file', type=str, required=True, help='The absolute path to the file to upload.')
args = parser.parse_args()
results = vtpy.analyze(args.file)
if results is None:
  print("Upload or analysis failed.")
else:
  pprint.PrettyPrinter(indent=4).print(results)