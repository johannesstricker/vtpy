from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from time import sleep
from contextlib import contextmanager
import os
import re


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


def wait_for_elem(driver, selectors, timeout = 10):
    try:
        return WebDriverWait(driver, timeout).until(lambda driver: find_element(driver, selectors))
    except:
        raise RuntimeError(f"Element not found: {selectors}")


@contextmanager
def get_driver(headless=False):
    options = Options()
    if headless:
        options.add_argument('--headless')
    options.add_argument('--log-level=3')
    driver = webdriver.Chrome(options=options)
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
    WebDriverWait(driver, 10).until(lambda x: id.text != '')
    result.id = id.text
    total = wait_for_elem(driver, ['vt-virustotal-app', 'file-view', 'vt-ui-main-generic-report', 'vt-ui-detections-widget', '.engines .circle .total'])
    WebDriverWait(driver, 10).until(lambda x: total.text != '')
    result.total_results = parse_int(total.text)
    malicious = wait_for_elem(driver, ['vt-virustotal-app', 'file-view', 'vt-ui-main-generic-report', 'vt-ui-detections-widget', '.engines .circle .positives'])
    WebDriverWait(driver, 10).until(lambda x: malicious.text != '')
    result.malicious_results = parse_int(malicious.text)
    result.detailed_results = get_detailed_results(driver)
    return result


def is_upload_page(driver):
    url = "https://www.virustotal.com/gui/file/"
    return url in driver.current_url


def get_upload_progress(driver, callback):
    upload_form = wait_for_elem(driver, ['vt-virustotal-app', 'home-view', 'vt-ui-main-upload-form', '.wrapper'])
    buttons = upload_form.find_elements_by_css_selector("vt-ui-button.blue.filled")
    progress = -1
    while progress < 100:
        found_match = False
        for button in buttons:
            matches = re.findall('Uploading (\d+)%', button.text)
            found_match = len(matches) > 0
            if found_match:
                value = int(matches[0])
                if value != progress:
                    callback(value)
                progress = value
                break
        if not found_match and progress > 0:
            callback(100)
            return


def set_upload_file(driver, file):
    input = wait_for_elem(driver, ['vt-virustotal-app', 'home-view', 'vt-ui-main-upload-form', '#fileSelector'])
    input.send_keys(os.path.realpath(file))
    sleep(1)


def accept_cookie_header(driver):
    button = find_element(driver, ['vt-virustotal-app', '#euConsent vt-ui-button'])
    button.click()
    sleep(1)


def confirm_upload(driver):
    button = wait_for_elem(driver, ['vt-virustotal-app', 'home-view', 'vt-ui-main-upload-form', '#confirmUpload'])
    WebDriverWait(driver, 10).until(lambda x: button.get_attribute('hidden') is None)
    button.click()
    sleep(1)


def print_progress(percent):
    if percent >= 100:
        print(f"Analysis in progress..")
    else:
        print(f"{percent}% completed..", end="\r")


def upload(file, headless=True, progress_callback = print_progress):
    with get_driver(headless) as driver:
        driver.get("https://virustotal.com")
        set_upload_file(driver, file)
        accept_cookie_header(driver)
        # Wait for the 'Confirm Upload' button. If it doesn't appear, the file might
        # have already been known and we have been redirected to the results page.
        confirm_upload(driver)
        get_upload_progress(driver, progress_callback)
        # During analysis the following url is present.
        # TODO: add detailed progression checks.
        # https://www.virustotal.com/gui/file-analysis/ZDJiMjhjMWI2NGZhMzc4MjYwZmYyMzdkMWI3NTA2NGM6MTU0NjUxODU2Mw==
        # Wait for success page.
        if not bool_wait(driver, 600, lambda driver: "https://www.virustotal.com/gui/file/" in driver.current_url):
            raise RuntimeError("Unexpected final url.")
        # pass url here and check if the page is already set or not
        results = get_results(driver)
        results.url = driver.current_url
        return results


def analyze(id, headless=True):
    url = f"https://www.virustotal.com/gui/file-analysis/{id}"
    with get_driver(headless) as driver:
        driver.get(url)


def detections(id, headless=True):
    url = f"https://www.virustotal.com/gui/file/{id}/detection"
    with get_driver(headless) as driver:
        driver.get(url)
        last_analysis = wait_for_elem(driver, ['vt-virustotal-app', 'file-view', 'vt-ui-main-generic-report', 'vt-ui-time-ago'])
        if last_analysis is None:
            print("Last analysis not found")
        else:
            print(last_analysis.text)
        return get_results(driver)
