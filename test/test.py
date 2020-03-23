import unittest
import tempfile
import random
from virustotal import virustotal


def random_bytes(length):
  return bytearray(random.getrandbits(8) for _ in range(length))


class IntegrationSpec(unittest.TestCase):
  def setUp(self):
    ONE_MEGABYTE = 100000
    self.file = tempfile.NamedTemporaryFile()
    self.file.write(random_bytes(ONE_MEGABYTE))

  def test_it_to_retrieve_results_from_virustotal(self):
    result = virustotal.upload(self.file.name, False)
    self.assertIsNot(result.id, '')
    self.assertGreater(result.total_results, 0)
    self.assertEqual(result.malicious_results, 0)
    for detection in result.detailed_results:
      self.assertFalse(detection.is_malicious())
    was_scanned = list(filter(lambda x: x.was_scanned(), result.detailed_results))
    self.assertEqual(result.total_results, len(was_scanned))
