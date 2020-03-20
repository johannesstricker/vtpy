#!/usr/bin/env python3
import argparse
import pprint
import virustotal


parser = argparse.ArgumentParser(description='Upload a file to virustotal.com and retrieve the url.')
parser.add_argument('--file', type=str, required=True, help='The absolute path to the file to upload.')
args = parser.parse_args()
# results = virustotal.upload(args.file, False)
results = virustotal.detections(args.file, False)
if results is None:
  print("Upload failed.")
else:
  pprint.PrettyPrinter(indent=4).print(results)