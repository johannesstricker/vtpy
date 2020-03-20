from specter import Spec, expect
import tempfile
import random
from virustotal import virustotal


def random_bytes(length):
  return bytearray(random.getrandbits(8) for _ in range(length))


class IntegrationSpec(Spec):
  def before_each(self):
    KILOBYTE = 1000
    SIZE_IN_KILOBYTES = 1000
    self.file = tempfile.NamedTemporaryFile()
    for i in range(SIZE_IN_KILOBYTES):
      self.file.write(random_bytes(KILOBYTE))
    print(f"File size is {self.file.tell()}")

  def it_to_retrieve_results_from_virustotal(self):
    results = virustotal.upload(self.file.name)
    expect('id' in results).to.be_true()
    expect(results['total_results']).to.be_greater_than(50)
    expect(results['malicious_results']).to.equal(0)
    for detection in results['detailed_results']:
      expect('name' in results).to_be_true()
      expect(detection['malicious']).to.be_false()
      expect(detection['details']).to.equal('Undetected')
