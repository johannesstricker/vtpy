from selenium.webdriver import Chrome
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from time import sleep
from contextlib import contextmanager
import os
import re


WAIT_TIME = 5
HASH_TIMEOUT = 10
UPLOAD_TIMEOUT = 300
ANALYSIS_TIMEOUT = 300


class VirusTotalResult:
    def __init__(self):
        self.id = 0
        self.total_results = 0
        self.malicious_results = 0
        self.detailed_results = []

    def __str__(self):
        return str(self.to_dict())

    def to_dict(self):
        return {
            "id": self.id,
            "url": self.url(),
            "total_results": self.total_results,
            "malicious_results": self.malicious_results,
            "detailed_results": list(map(lambda x: x.to_dict(), self.detailed_results))
        }

    def url(self):
        return f"https://www.virustotal.com/gui/file/{self.id}/detection"


class VirusTotalDetection:
    UNDETECTED = 'Undetected'
    UNABLE_TO_PROCESS = [
        'Unable to process file type',
        'Timeout',
        'Confirmed timeout',
        ''
    ]

    def __init__(self, name, details):
        self.name = name
        self.details = details

    def __str__(self):
        return str(self.to_dict())

    def to_dict(self):
        return {
            "name": self.name,
            "is_malicious": self.is_malicious(),
            "was_scanned": self.was_scanned(),
            "details": self.details
        }

    def is_malicious(self):
        return self.details != self.UNDETECTED and self.details not in self.UNABLE_TO_PROCESS

    def was_scanned(self):
        return self.details not in self.UNABLE_TO_PROCESS


@contextmanager
def webdriver(headless=False):
    options = Options()
    options.add_experimental_option('excludeSwitches', ['enable-logging'])
    if headless:
        options.add_argument('--headless')
    options.add_argument('--log-level=3')
    driver = Chrome(options=options)
    yield driver
    driver.quit()


def find_element(driver, selectors):
    def expand_shadow_element(driver, element):
        return driver.execute_script('return arguments[0].shadowRoot', element)
    element = driver.find_element_by_css_selector(selectors[0])
    for selector in selectors[1:]:
        element = expand_shadow_element(driver, element) or element
        element = element.find_element_by_css_selector(selector)
    return element


def wait_for_elem(driver, selectors, timeout = WAIT_TIME):
    try:
        return WebDriverWait(driver, timeout).until(lambda driver: find_element(driver, selectors))
    except:
        raise RuntimeError(f"Element not found: {selectors}")


def get_detection_details(driver):
    def get_single_detection(element):
        name = element.find_element_by_css_selector('.engine-name').text
        details = element.find_element_by_css_selector('.individual-detection').text
        return VirusTotalDetection(name, details)
    detections_list = wait_for_elem(driver, ['file-view', 'vt-ui-detections-list', '#detections'])
    detections = detections_list.find_elements_by_css_selector('.detection')
    return list(map(get_single_detection, detections))


def validate_analysis_results(results):
    num_total = len([x for x in results.detailed_results if x.was_scanned()])
    num_malicious = len([x for x in results.detailed_results if x.is_malicious()])
    if num_total != results.total_results:
        raise RuntimeError(f"Invalid analysis results: expected {results.total_results} scan results, but got {num_total}!")
    if num_malicious != results.malicious_results:
        raise RuntimeError(f"Invalid analysis results: expected {results.malicious_results} malicious scan results, but got {num_malicious}!")


def get_analysis_results(driver):
    def extract_int(value):
        digits = '0123456789'
        return int(''.join([x for x in value if x in digits]))
    result = VirusTotalResult()
    file_id_element = wait_for_elem(driver, ['file-view', 'vt-ui-file-card', '.file-id'])
    WebDriverWait(driver, WAIT_TIME).until(lambda x: file_id_element.text != '')
    result.id = file_id_element.text
    total_element = wait_for_elem(driver, ['file-view', 'vt-ui-main-generic-report', 'vt-ui-detections-widget', '.engines .circle .total'])
    WebDriverWait(driver, WAIT_TIME).until(lambda x: total_element.text != '')
    result.total_results = extract_int(total_element.text)
    malicious_element = wait_for_elem(driver, ['file-view', 'vt-ui-main-generic-report', 'vt-ui-detections-widget', '.engines .circle .positives'])
    WebDriverWait(driver, WAIT_TIME).until(lambda x: malicious_element.text != '')
    result.malicious_results = extract_int(malicious_element.text)
    result.detailed_results = get_detection_details(driver)
    validate_analysis_results(result)
    return result


def set_upload_file(driver, file):
    input = wait_for_elem(driver, ['home-view', 'vt-ui-main-upload-form', '#fileSelector'])
    sleep(1)
    input.send_keys(os.path.realpath(file))
    sleep(1)


def accept_cookie_header(driver):
    button = find_element(driver, ['vt-ui-shell', '#euConsent vt-ui-button'])
    try:
        button.click()
    except:
        pass
    sleep(1)


def wait_until_hash_computed(driver):
    hash_button = get_hash_progress_button(driver)
    def hash_finished(driver):
        return get_progress_from_button(hash_button) >= 100 or is_results_page(driver)
    WebDriverWait(driver, HASH_TIMEOUT).until(hash_finished)
    sleep(1)


def get_hash_progress_button(driver):
    upload_form = wait_for_elem(driver, ['home-view', 'vt-ui-main-upload-form', '.wrapper'])
    if upload_form is None:
        return None
    buttons = upload_form.find_elements_by_css_selector("vt-ui-button.blue.filled")
    buttons = list(filter(lambda x: 'Computing hash' in x.get_attribute('innerHTML'), buttons))
    if len(buttons) == 0:
        return None
    return buttons[0]


def is_results_page(driver):
    url = "https://www.virustotal.com/gui/file/"
    return url in driver.current_url


def confirm_upload(driver):
    button = wait_for_elem(driver, ['home-view', 'vt-ui-main-upload-form', '#confirmUpload'])
    WebDriverWait(driver, WAIT_TIME).until(lambda x: button.get_attribute('hidden') is None)
    button.click()
    sleep(1)


def wait_until_upload_finished(driver, callback):
    def update_progress_and_check_analysis_page(driver):
        progress_button = get_upload_progress_button(driver)
        progress = get_progress_from_button(progress_button)
        callback(progress)
        return is_analysis_page(driver)
    WebDriverWait(driver, UPLOAD_TIMEOUT).until(update_progress_and_check_analysis_page)
    callback(100)


def wait_until_analysis_finished(driver):
    WebDriverWait(driver, ANALYSIS_TIMEOUT).until(is_results_page)


def get_upload_progress_button(driver):
    upload_form = wait_for_elem(driver, ['home-view', 'vt-ui-main-upload-form', '.wrapper'])
    if upload_form is None:
        return None
    buttons = upload_form.find_elements_by_css_selector("vt-ui-button.blue.filled")
    buttons = list(filter(lambda x: 'Uploading' in x.get_attribute('innerHTML'), buttons))
    if len(buttons) == 0:
        return None
    return buttons[0]


def is_analysis_page(driver):
    url = "https://www.virustotal.com/gui/file-analysis/"
    return url in driver.current_url


def get_progress_from_button(button):
    if button is None:
        return -1
    matches = re.findall('(\d+)%', button.get_attribute('innerHTML'))
    if len(matches) > 0:
        return int(matches[0])
    return -1


def analyze(file, headless=True, progress_callback = lambda percent_complete: None):
    with webdriver(False) as driver:
        driver.get("https://virustotal.com")
        set_upload_file(driver, file)
        wait_until_hash_computed(driver)
        accept_cookie_header(driver)
        if not is_results_page(driver):
            confirm_upload(driver)
            wait_until_upload_finished(driver, progress_callback)
            wait_until_analysis_finished(driver)
        return get_analysis_results(driver)
