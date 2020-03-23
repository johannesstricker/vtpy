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

    def url(self):
        return f"https://www.virustotal.com/gui/file/{self.id}/detection"
        # return f"https://www.virustotal.com/gui/file-analysis/{self.id}/detection"


class VirusTotalDetection:
    UNDETECTED = 'Undetected'
    NOT_PROCESSED = 'Unable to process file type'

    def __init__(self, name, details):
        self.name = name
        self.details = details

    def is_malicious(self):
        return self.details not in [self.UNDETECTED, self.NOT_PROCESSED]

    def was_scanned(self):
        return self.details != self.NOT_PROCESSED


class VirusTotalUploadPage:
    def __init__(self, driver):
        self.driver = driver

    def open(self):
        self.driver.get("https://virustotal.com")

    def set_upload_file(self, file):
        pass

    def accept_cookie_header(self):
        pass

    def confirm_upload(self):
        pass

    def wait_for_upload(self, callback = lambda x: print(x)):
        pass

class VirusTotalResultsPage:
    def __init__(self, driver):
        self.driver = driver

    def file_id(self):
        pass

    def detection_count(self):
        pass

    def malicious_detection_count(self):
        pass

    def detections(self):
        pass




def find_element(driver, selectors):
    element = driver.find_element_by_css_selector(selectors[0])
    for selector in selectors[1:]:
        element = expand_shadow_element(driver, element) or element
        element = element.find_element_by_css_selector(selector)
    return element


def expand_shadow_element(driver, element):
  shadow_root = driver.execute_script('return arguments[0].shadowRoot', element)
  return shadow_root


def bool_wait(driver, timeout, func):
    try:
        WebDriverWait(driver, timeout).until(func)
    except:
        return False
    return True


def wait_for_elem(driver, selectors, timeout = WAIT_TIME):
    try:
        return WebDriverWait(driver, timeout).until(lambda driver: find_element(driver, selectors))
    except:
        raise RuntimeError(f"Element not found: {selectors}")


@contextmanager
def webdriver(headless=False):
    options = Options()
    if headless:
        options.add_argument('--headless')
    options.add_argument('--log-level=3')
    driver = Chrome(options=options)
    yield driver
    driver.quit()


def get_shadow_parent(driver, tags):
    root = None
    shadow = driver
    for tag in tags:
        root = shadow.find_element_by_css_selector(tag)
        if root is None:
            print(f'{tag} not found!')
            return None
        shadow = expand_shadow_element(driver, root)
        if shadow is None:
            print(f'Shadow not found for {tag}')
            shadow = root
    return shadow

def get_shadow_parent_for_id(driver):
    tags = ['vt-virustotal-app', 'file-view', 'vt-ui-main-generic-report', 'vt-ui-file-card']
    return get_shadow_parent(driver, tags)


def get_shadow_parent_for_generic_results(driver):
    tags = ['vt-virustotal-app', 'file-view', 'vt-ui-main-generic-report', 'vt-ui-detections-widget']
    return get_shadow_parent(driver, tags)


def get_shadow_parent_for_detailed_results(driver):
    tags = ['vt-virustotal-app', 'file-view', 'vt-ui-detections-list']
    return get_shadow_parent(driver, tags)


def parse_int(value):
    digits = '0123456789'
    return int(''.join([x for x in value if x in digits]))


def parse_detection(elem):
    name = elem.find_element_by_css_selector('.engine-name').text
    details = elem.find_element_by_css_selector('.individual-detection').text
    return VirusTotalDetection(name, details)


def get_detailed_results(driver):
    shadow = get_shadow_parent_for_detailed_results(driver)
    detections = shadow.find_elements_by_css_selector('.detection')
    return list(map(parse_detection, detections))


def get_results(driver):
    result = VirusTotalResult()
    id = wait_for_elem(driver, ['vt-virustotal-app', 'file-view', 'vt-ui-main-generic-report', 'vt-ui-file-card', '.file-id'])
    WebDriverWait(driver, WAIT_TIME).until(lambda x: id.text != '')
    result.id = id.text
    total = wait_for_elem(driver, ['vt-virustotal-app', 'file-view', 'vt-ui-main-generic-report', 'vt-ui-detections-widget', '.engines .circle .total'])
    WebDriverWait(driver, WAIT_TIME).until(lambda x: total.text != '')
    result.total_results = parse_int(total.text)
    malicious = wait_for_elem(driver, ['vt-virustotal-app', 'file-view', 'vt-ui-main-generic-report', 'vt-ui-detections-widget', '.engines .circle .positives'])
    WebDriverWait(driver, WAIT_TIME).until(lambda x: malicious.text != '')
    result.malicious_results = parse_int(malicious.text)
    result.detailed_results = get_detailed_results(driver)
    return result


def set_upload_file(driver, file):
    input = wait_for_elem(driver, ['vt-virustotal-app', 'home-view', 'vt-ui-main-upload-form', '#fileSelector'])
    input.send_keys(os.path.realpath(file))
    sleep(1)


def accept_cookie_header(driver):
    button = find_element(driver, ['vt-virustotal-app', '#euConsent vt-ui-button'])
    button.click()
    sleep(1)


def wait_until_hash_computed(driver):
    hash_button = get_hash_progress_button(driver)
    def hash_finished(driver):
        return get_progress_from_button(hash_button) >= 100 or is_results_page(driver)
    WebDriverWait(driver, HASH_TIMEOUT).until(hash_finished)
    sleep(1)


def get_hash_progress_button(driver):
    upload_form = wait_for_elem(driver, ['vt-virustotal-app', 'home-view', 'vt-ui-main-upload-form', '.wrapper'])
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
    button = wait_for_elem(driver, ['vt-virustotal-app', 'home-view', 'vt-ui-main-upload-form', '#confirmUpload'])
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
    upload_form = wait_for_elem(driver, ['vt-virustotal-app', 'home-view', 'vt-ui-main-upload-form', '.wrapper'])
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
    with webdriver(headless) as driver:
        driver.get("https://virustotal.com")
        set_upload_file(driver, file)
        wait_until_hash_computed(driver)
        accept_cookie_header(driver)
        if not is_results_page(driver):
            confirm_upload(driver)
            wait_until_upload_finished(driver, progress_callback)
            wait_until_analysis_finished(driver)
        return get_results(driver)
