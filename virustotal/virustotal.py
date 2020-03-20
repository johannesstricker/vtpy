from selenium import webdriver
from time import sleep
import selenium.webdriver.support.ui as ui
from selenium.webdriver.chrome.options import Options
from contextlib import contextmanager
import os
import re


def find_element(driver, selectors):
    element = None
    for selector in selectors:
        if element is None:
            element = driver.find_element_by_css_selector(selector)
        else:
            element = element.find_element_by_css_selector(selector)
        element = expand_shadow_element(driver, element) or element
    return element


def bool_wait(driver, timeout, func):
    wait = ui.WebDriverWait(driver, timeout)
    try:
        wait.until(func)
    except:
        return False
    return True


def wait_for_elem(driver, selectors, timeout = 10):
    wait = ui.WebDriverWait(driver, timeout)
    try:
        wait.until(lambda driver: find_element(driver, selectors))
    except:
        return None
    return driver.find_elements_by_css_selector(' '.join(selectors))
    # return find_element(driver, selectors)


@contextmanager
def get_driver(headless=False):
    options = Options()
    if headless:
        options.add_argument('--headless')
    options.add_argument('--log-level=3')
    driver = webdriver.Chrome(chrome_options=options)
    yield driver
    driver.quit()


def expand_shadow_element(driver, element):
  shadow_root = driver.execute_script('return arguments[0].shadowRoot', element)
  return shadow_root


def get_upload_field(shadow, driver):
    return shadow.find_element_by_css_selector('#fileSelector')


def get_upload_button(shadow, driver):
    return shadow.find_element_by_css_selector('#confirmUpload')


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


def get_shadow_parent_for_upload(driver):
    tags = ['vt-virustotal-app', 'home-view', 'vt-ui-main-upload-form']
    return get_shadow_parent(driver, tags)


def is_upload_button_visible(shadow, driver):
    return get_upload_button(shadow, driver).get_attribute("hidden") is None


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
    malicious = details != 'Undetected'
    return dict(name = name, details = details, malicious = malicious)


def get_general_results(driver):
    shadow = get_shadow_parent_for_id(driver)
    file_id = shadow.find_element_by_css_selector('.file-id').text
    shadow = get_shadow_parent_for_generic_results(driver)
    total = parse_int(shadow.find_element_by_css_selector('.total').text)
    malicious = parse_int(shadow.find_element_by_css_selector('.positives').text)
    return { 'id': file_id, 'total_results': total, 'malicious_results': malicious }


def get_detailed_results(driver):
    shadow = get_shadow_parent_for_detailed_results(driver)
    detections = shadow.find_elements_by_css_selector('.detection')
    return { 'detailed_results': list(map(parse_detection, detections)) }


def get_results(driver):
    return { **get_general_results(driver), **get_detailed_results(driver) }


def is_upload_page(driver):
    url = "https://www.virustotal.com/gui/file/"
    return url in driver.current_url


def get_upload_progress(driver, callback):
    shadow = get_shadow_parent_for_upload(driver)
    buttons = shadow.find_elements_by_css_selector("vt-ui-button.blue.filled")
    pattern = 'Uploading (\d+)%'
    for button in buttons:
        matches = re.findall('Uploading (\d+)%', button.text)
        if len(matches) == 0:
            continue
        progress = -1
        while progress < 100:
            value = int(matches[0])
            if value != progress:
                progress = value
                callback(progress)
            matches = re.findall('Uploading (\d+)%', button.text)


def print_progress(percent):
    if percent == 100:
        print(f"Analysis in progress..")
    else:
        print(f"{percent}% completed..", end="\r")


def upload(file, headless=True, progress_callback = print_progress):
    with get_driver(headless) as driver:
        driver.get("https://virustotal.com")
        # Wait for the shadow dom.
        if not bool_wait(driver, 10, lambda driver: get_shadow_parent_for_upload(driver)):
            return None
        shadow = get_shadow_parent_for_upload(driver)
        # Wait for the file input.
        if not bool_wait(driver, 10, lambda driver: get_upload_field(shadow, driver)):
            return None
        input = get_upload_field(shadow, driver)
        input.send_keys(os.path.realpath(file))
        # Wait for the 'Confirm Upload' button. If it doesn't appear, the file might
        # have already been known and we have been redirected to the results page.
        if not bool_wait(driver, 10, lambda driver:  is_upload_button_visible(shadow, driver)):
            return None
        button = get_upload_button(shadow, driver)
        button.click()
        get_upload_progress(driver, progress_callback)
        # During analysis the following url is present.
        # TODO: add detailed progression checks.
        # https://www.virustotal.com/gui/file-analysis/ZDJiMjhjMWI2NGZhMzc4MjYwZmYyMzdkMWI3NTA2NGM6MTU0NjUxODU2Mw==
        # Wait for success page.
        if not bool_wait(driver, 600, lambda driver: "https://www.virustotal.com/gui/file/" in driver.current_url):
            print("Unexpected final url.")
            return None
        results = get_results(driver)
        return { 'url': driver.current_url, **results }


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