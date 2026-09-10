"""App info screen snapshot test.

Snapshots the "Version" info field (Version / Developer / Copyright, defined
in ui_idle_menu_nbgl.c's infoList), reached from the home screen on every
device.
"""
from application_client.settings import _TOUCH_POSITIONS
from ragger.navigator import NavInsID


def _info_page(device):
    # Info is the page right after the switches list, whatever page count
    # the switches take on this device (1 on Stax, 2 on Flex/Apex).
    pages = {page for page, _, _ in _TOUCH_POSITIONS[device.type].values()}
    return max(pages) + 1


def test_app_info_version(backend, device, navigator, default_screenshot_path, test_name):
    if device.is_nano:
        navigator.navigate_and_compare(
            default_screenshot_path, test_name,
            [NavInsID.RIGHT_CLICK, NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK],
            screen_change_before_first_instruction=False)
        # Step past "Developer" and "Copyright" to "Back", then validate.
        navigator.navigate([NavInsID.RIGHT_CLICK] * 3 + [NavInsID.BOTH_CLICK],
                            screen_change_before_first_instruction=False)
    else:
        page = _info_page(device)
        navigator.navigate_and_compare(
            default_screenshot_path, test_name,
            [NavInsID.USE_CASE_HOME_SETTINGS] + [NavInsID.USE_CASE_SETTINGS_NEXT] * page,
            screen_change_before_first_instruction=False)
        navigator.navigate([NavInsID.USE_CASE_SETTINGS_MULTI_PAGE_EXIT],
                            screen_change_before_first_instruction=False)
