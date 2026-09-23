import re

from phishhawk import banner

ANSI = re.compile(r"\033\[[0-9;]*m")


def visible(text):
    return ANSI.sub("", text)


def test_side_by_side_fits_eighty_columns():
    art = banner.render(colour=False, width=80)
    lines = art.splitlines()
    assert max(len(line) for line in lines) <= 80
    assert any("d8888b." in line for line in lines)   # PHISH lettering
    assert any("I8I" in line for line in lines)       # HAWK lettering
    assert any("O" in line for line in lines)         # the hawk's eye


def test_it_degrades_with_the_terminal():
    assert "d8888b." in banner.render(colour=False, width=60)
    assert "UX" not in banner.render(colour=False, width=60)   # emblem dropped
    one_line = banner.render(colour=False, width=30)
    assert one_line.count("\n") == 1 and "PhishHawk" in one_line


def test_colour_is_optional_and_does_not_change_layout():
    coloured = banner.render(colour=True, width=80)
    assert "\033[38;5;" in coloured
    assert "\033[" not in banner.render(colour=False, width=80)
    assert visible(coloured) == banner.render(colour=False, width=80)
