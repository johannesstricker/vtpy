# vtpy - virustotal.com upload
[![Actions Status](https://github.com/johannesstricker/vtpy/workflows/vtpy/badge.svg)](https://github.com/johannesstricker/vtpy/actions)

## Installation
vtpy is not published on PyPI, which means you have to download or clone the repository. Additionally,
vtpy requires [chromedriver](https://sites.google.com/a/chromium.org/chromedriver/) to be installed.

## Usage
You can use vtpy directly from the command line.
```
python -m vtpy --file path/to/your/file
```
The result will look similar to
```
{
  id: <file_id>,
  total_results: 51,
  malicious_results: 0,
  detailed_results: [
    { name: "Bkav", details: "Undetected" },
    { name: "Kasperky", details: "Undetected" },
    ...
  ]
}
```

Alternatively, you can use vtpy from within your python projects. Copy the `vtpy` folder into your
project folder, then
```
from vtpy import vtpy

vtpy.analyze("path/to/your/file")
```

## License
[MIT](https://github.com/johannesstricker/vtpy/blob/master/LICENSE)