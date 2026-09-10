"""Settings screen snapshot tests, one test per setting.

Snapshots each switch (Transactions data / Custom contracts / Blind signing),
off and on, on every device. This is a regression guard for bugs like the one
where "Blind signing"'s label rendered but its switch control was clipped
off-screen on Nano.
"""
from application_client.settings import SettingID, _ORDER, _TOUCH_POSITIONS, settings_toggle
from ragger.navigator import NavInsID


def _snap_nano(navigator, screenshot_path, test_name, state, index, from_home):
    # From the home screen, "App settings" is one RIGHT_CLICK away. Once
    # already inside the switches list flow, re-entering only needs BOTH_CLICK.
    enter = [NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK] if from_home else [NavInsID.BOTH_CLICK]
    navigator.navigate_and_compare(
        screenshot_path, f"{test_name}/{state}",
        enter + [NavInsID.RIGHT_CLICK] * index,
        screen_change_before_first_instruction=False)
    # Walk to "Back" and validate: return to the "App settings" home entry.
    navigator.navigate([NavInsID.RIGHT_CLICK] * (len(_ORDER) - index) + [NavInsID.BOTH_CLICK],
                        screen_change_before_first_instruction=False)


def _toggle_nano(navigator, index, from_home):
    enter = [NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK] if from_home else [NavInsID.BOTH_CLICK]
    navigator.navigate(enter + [NavInsID.RIGHT_CLICK] * index,
                        screen_change_before_first_instruction=False)
    # Toggling validates in place. Some switches (e.g. "Blind signing") do not
    # repaint on Nano, so we must not wait for a screen change here.
    navigator.navigate([NavInsID.BOTH_CLICK],
                        screen_change_before_first_instruction=False,
                        screen_change_after_last_instruction=False)
    navigator.navigate([NavInsID.RIGHT_CLICK] * (len(_ORDER) - index) + [NavInsID.BOTH_CLICK],
                        screen_change_before_first_instruction=False)


def _snap_touch(device, navigator, screenshot_path, test_name, state, setting):
    page = _TOUCH_POSITIONS[device.type][setting][0]
    navigator.navigate_and_compare(
        screenshot_path, f"{test_name}/{state}",
        [NavInsID.USE_CASE_HOME_SETTINGS] + [NavInsID.USE_CASE_SETTINGS_NEXT] * page,
        screen_change_before_first_instruction=False)
    navigator.navigate([NavInsID.USE_CASE_SETTINGS_MULTI_PAGE_EXIT],
                        screen_change_before_first_instruction=False)


def _run_setting_test(device, navigator, screenshot_path, test_name, setting):
    if device.is_nano:
        index = _ORDER.index(setting)
        _snap_nano(navigator, screenshot_path, test_name, "off", index, from_home=True)
        _toggle_nano(navigator, index, from_home=False)
        _snap_nano(navigator, screenshot_path, test_name, "on", index, from_home=False)
    else:
        _snap_touch(device, navigator, screenshot_path, test_name, "off", setting)
        settings_toggle(device, navigator, [setting])
        _snap_touch(device, navigator, screenshot_path, test_name, "on", setting)


def test_settings_transactions_data(backend, device, navigator, default_screenshot_path, test_name):
    _run_setting_test(device, navigator, default_screenshot_path, test_name, SettingID.DATA_ALLOWED)


def test_settings_custom_contracts(backend, device, navigator, default_screenshot_path, test_name):
    _run_setting_test(device, navigator, default_screenshot_path, test_name, SettingID.CUSTOM_CONTRACT)


def test_settings_blind_signing(backend, device, navigator, default_screenshot_path, test_name):
    _run_setting_test(device, navigator, default_screenshot_path, test_name, SettingID.SIGN_BY_HASH)
