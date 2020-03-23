import unittest
import tempfile
import random
from virustotal import virustotal


class IntegrationSpec(unittest.TestCase):
  @classmethod
  def setUpClass(cls):
    def random_bytes(length):
      return bytearray(random.getrandbits(8) for _ in range(length))
    FILE_SIZE_BYTES = 100000
    cls.file = tempfile.NamedTemporaryFile()
    cls.file.write(random_bytes(FILE_SIZE_BYTES))

  def test_analyze_local_file(self):
    scan_results = virustotal.analyze(self.file.name)
    self.assertIsNot(scan_results.id, '')
    self.assertGreater(scan_results.total_results, 0)
    # ensure that the number of malicious results is correct
    is_malicious = len([x for x in scan_results.detailed_results if x.is_malicious()])
    self.assertEqual(scan_results.malicious_results, is_malicious)
    # ensure that the total number of scan results is correct
    was_scanned = len([x for x in scan_results.detailed_results if x.was_scanned()])
    self.assertEqual(scan_results.total_results, was_scanned)
    # ensure that the same file can be analyzed twice
    self.assertEqual(scan_results.id, virustotal.analyze(self.file.name).id)