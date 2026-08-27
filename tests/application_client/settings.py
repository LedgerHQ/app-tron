"""Inline settings toggling, mirroring app-ethereum's settings helper.

Tests enable only the settings they need, instead of a global fixture flipping
everything through the UI.
"""
from enum import Enum, auto

from ledgered.devices import Device, DeviceType
from ragger.navigator import Navigator, NavIns, NavInsID


class SettingID(Enum):
    DATA_ALLOWED = auto()      # "Transactions data"
    CUSTOM_CONTRACT = auto()   # "Custom contracts"
    SIGN_BY_HASH = auto()      # "Blind signing"


# Settings are a single switches list, in this order, on every device.
_ORDER = [SettingID.DATA_ALLOWED, SettingID.CUSTOM_CONTRACT, SettingID.SIGN_BY_HASH]

# Touch devices: (page, x, y) of each switch.
_TOUCH_POSITIONS = {
    DeviceType.STAX: {
        SettingID.DATA_ALLOWED: (0, 200, 150),
        SettingID.CUSTOM_CONTRACT: (0, 200, 300),
        SettingID.SIGN_BY_HASH: (0, 200, 450),
    },
    DeviceType.FLEX: {
        SettingID.DATA_ALLOWED: (0, 200, 150),
        SettingID.CUSTOM_CONTRACT: (0, 200, 300),
        SettingID.SIGN_BY_HASH: (1, 200, 150),
    },
    DeviceType.APEX_P: {
        SettingID.DATA_ALLOWED: (0, 150, 110),
        SettingID.CUSTOM_CONTRACT: (0, 150, 220),
        SettingID.SIGN_BY_HASH: (1, 150, 110),
    },
}


def _toggle_nano(navigator: Navigator, to_toggle: list[SettingID]) -> None:
    # Home -> "App settings" -> enter the switches list.
    navigator.navigate([NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK],
                       screen_change_before_first_instruction=False)
    for setting in _ORDER:
        if setting in to_toggle:
            # Toggling a switch validates in place. Some switches (e.g. "Blind signing")
            # do not repaint on Nano, so we must not wait for a screen change here.
            navigator.navigate([NavInsID.BOTH_CLICK],
                               screen_change_before_first_instruction=False,
                               screen_change_after_last_instruction=False)
        # Advance to the next switch (or to "Back" after the last one).
        navigator.navigate([NavInsID.RIGHT_CLICK], screen_change_before_first_instruction=False)
    # On "Back": return to the home screen.
    navigator.navigate([NavInsID.BOTH_CLICK], screen_change_before_first_instruction=False)


def _toggle_touch(device: Device, navigator: Navigator, to_toggle: list[SettingID]) -> None:
    positions = _TOUCH_POSITIONS[device.type]
    moves: list = [NavInsID.USE_CASE_HOME_SETTINGS]
    current_page = 0
    for setting in _ORDER:
        if setting in to_toggle:
            page, x, y = positions[setting]
            moves += [NavInsID.USE_CASE_SETTINGS_NEXT] * (page - current_page)
            moves += [NavIns(NavInsID.TOUCH, (x, y))]
            current_page = page
    moves += [NavInsID.USE_CASE_SETTINGS_MULTI_PAGE_EXIT]
    navigator.navigate(moves, screen_change_before_first_instruction=False)


def settings_toggle(device: Device, navigator: Navigator, to_toggle: list[SettingID]) -> None:
    if device.is_nano:
        _toggle_nano(navigator, to_toggle)
    else:
        _toggle_touch(device, navigator, to_toggle)
