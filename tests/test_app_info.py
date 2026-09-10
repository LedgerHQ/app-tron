"""App info screen snapshot test.

Snapshots all three info fields (Version / Developer / Copyright, defined in
ui_idle_menu_nbgl.c's infoList) on every device. Flex and Apex spread them
over two info pages; Stax fits all three on one; Nano steps through them.
"""
from application_client.settings import _TOUCH_POSITIONS
from ledgered.devices import DeviceType
from ragger.navigator import NavInsID

_MULTI_PAGE_INFO_DEVICES = (DeviceType.FLEX, DeviceType.APEX_P)


def _first_info_page(device):
    pages = {page for page, _, _ in _TOUCH_POSITIONS[device.type].values()}
    return max(pages) + 1


def test_app_info(backend, device, navigator, default_screenshot_path, test_name):
    if device.is_nano:
        navigator.navigate_and_compare(
            default_screenshot_path, test_name,
            [NavInsID.RIGHT_CLICK, NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK,
             NavInsID.RIGHT_CLICK, NavInsID.RIGHT_CLICK],
            screen_change_before_first_instruction=False)
        navigator.navigate([NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK],
                            screen_change_before_first_instruction=False)
    else:
        instructions = [NavInsID.USE_CASE_HOME_SETTINGS]
        instructions += [NavInsID.USE_CASE_SETTINGS_NEXT] * _first_info_page(device)
        if device.type in _MULTI_PAGE_INFO_DEVICES:
            instructions.append(NavInsID.USE_CASE_SETTINGS_NEXT)
        navigator.navigate_and_compare(
            default_screenshot_path, test_name, instructions,
            screen_change_before_first_instruction=False)
        navigator.navigate([NavInsID.USE_CASE_SETTINGS_MULTI_PAGE_EXIT],
                            screen_change_before_first_instruction=False)
