# Tests for schedule.py. Runs on the router's Python 2.7 and on Python 3:
#   python -m unittest discover -s tests -t .
import os
import sqlite3
import time
import unittest

# US Eastern, so the DST cases are deterministic. SRM's Python has no
# time.tzset(), so there TZ must already be set when Python starts -
# tests/run_on_router.sh does that.
EASTERN = 'EST5EDT,M3.2.0,M11.1.0'
if hasattr(time, 'tzset'):
    os.environ['TZ'] = EASTERN
    time.tzset()
elif os.environ.get('TZ') != EASTERN:
    raise RuntimeError('run with TZ=%s set (time.tzset() is unavailable here)' % EASTERN)

from schedule import get_schedule_window  # noqa: E402 - must follow tzset()

PROFILE = 1


def at(text):
    # Local wall-clock time 'YYYY-MM-DD HH:MM' -> epoch seconds.
    return int(time.mktime(time.strptime(text, '%Y-%m-%d %H:%M')))


def local(epoch):
    return time.strftime('%a %Y-%m-%d %H:%M', time.localtime(epoch))


class ScheduleWindowTest(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(':memory:')
        self.db.execute(
            'CREATE TABLE schedule (profile_id INTEGER, begin_weekday INTEGER, end_weekday INTEGER, '
            'begin_clock INTEGER, end_clock INTEGER, type INTEGER)')

    def block(self, begin_weekday, begin_clock, end_weekday, end_clock, schedule_type=3):
        self.db.execute('INSERT INTO schedule VALUES (?, ?, ?, ?, ?, ?)',
                        (PROFILE, begin_weekday, end_weekday, begin_clock, end_clock, schedule_type))

    def daily_blocks(self, until_clock, from_clock):
        # Blocked midnight -> until_clock and from_clock -> midnight, every day.
        for day in range(7):
            self.block(day, 0, day, until_clock)
            self.block(day, from_clock, day, 2400)

    def window(self, now_text):
        state, start, end = get_schedule_window(self.db, PROFILE, at(now_text))
        return state, start and local(start), end and local(end)

    def test_no_blocks_is_always_on(self):
        self.assertEqual(self.window('2026-10-03 12:00'), ('always_on', None, None))

    def test_whole_week_blocked_is_always_off(self):
        for day in range(7):
            self.block(day, 0, day, 2400)
        self.assertEqual(self.window('2026-10-03 12:00'), ('always_off', None, None))

    def test_other_schedule_types_are_ignored(self):
        self.block(0, 0, 6, 2400, schedule_type=1)  # a filter schedule, not blocktime
        self.assertEqual(self.window('2026-10-03 12:00'), ('always_on', None, None))

    def test_blocked_before_morning_shows_todays_window(self):
        self.daily_blocks(600, 2100)
        self.assertEqual(self.window('2026-10-03 05:59'),
                         ('off', 'Sat 2026-10-03 06:00', 'Sat 2026-10-03 21:00'))

    def test_window_start_is_inclusive(self):
        self.daily_blocks(600, 2100)
        self.assertEqual(self.window('2026-10-03 06:00'),
                         ('on', 'Sat 2026-10-03 06:00', 'Sat 2026-10-03 21:00'))

    def test_window_end_is_exclusive(self):
        self.daily_blocks(600, 2100)
        self.assertEqual(self.window('2026-10-03 21:00'),
                         ('off', 'Sun 2026-10-04 06:00', 'Sun 2026-10-04 21:00'))

    def test_saturday_night_rolls_into_sunday(self):
        self.daily_blocks(600, 2100)
        self.assertEqual(self.window('2026-10-03 23:30'),
                         ('off', 'Sun 2026-10-04 06:00', 'Sun 2026-10-04 21:00'))

    def test_block_spanning_saturday_to_sunday_in_one_row(self):
        self.block(6, 2200, 0, 800)  # Sat 22:00 -> Sun 08:00
        self.assertEqual(self.window('2026-10-03 23:00')[0], 'off')
        self.assertEqual(self.window('2026-10-03 23:00')[1], 'Sun 2026-10-04 08:00')
        self.assertEqual(self.window('2026-10-04 07:59')[1], 'Sun 2026-10-04 08:00')
        # Allowed the rest of the week, so the current window started last Sunday.
        self.assertEqual(self.window('2026-10-03 12:00'),
                         ('on', 'Sun 2026-09-27 08:00', 'Sat 2026-10-03 22:00'))

    def test_single_short_weekly_slot(self):
        # Blocked all week except Thursday 17:45-19:15.
        self.block(0, 0, 4, 1745)
        self.block(4, 1915, 6, 2400)
        self.assertEqual(self.window('2026-10-03 12:00'),
                         ('off', 'Thu 2026-10-08 17:45', 'Thu 2026-10-08 19:15'))
        self.assertEqual(self.window('2026-10-08 18:00'),
                         ('on', 'Thu 2026-10-08 17:45', 'Thu 2026-10-08 19:15'))

    def test_adjacent_blocks_merge(self):
        # Two touching blocks are one blocked period, not a zero-length window.
        self.block(1, 0, 1, 1200)
        self.block(1, 1200, 1, 1800)
        self.assertEqual(self.window('2026-10-05 13:00'),
                         ('off', 'Mon 2026-10-05 18:00', 'Mon 2026-10-12 00:00'))

    def test_fall_back_day_keeps_wall_clock_times(self):
        # 2026-11-01 is the Sunday DST ends (2:00 -> 1:00); 6:00/21:00 must stay 6:00/21:00.
        self.daily_blocks(600, 2100)
        self.assertEqual(self.window('2026-11-01 05:00'),
                         ('off', 'Sun 2026-11-01 06:00', 'Sun 2026-11-01 21:00'))

    def test_spring_forward_day_keeps_wall_clock_times(self):
        # 2026-03-08 is the Sunday DST starts (2:00 -> 3:00).
        self.daily_blocks(600, 2100)
        self.assertEqual(self.window('2026-03-08 05:00'),
                         ('off', 'Sun 2026-03-08 06:00', 'Sun 2026-03-08 21:00'))

    def test_window_crossing_dst_change(self):
        # Allowed overnight Sat 20:00 -> Sun 08:00 across the fall-back night.
        for day in range(7):
            if day == 6:
                self.block(6, 0, 6, 2000)
            elif day == 0:
                self.block(0, 800, 0, 2400)
            else:
                self.block(day, 0, day, 2400)
        self.assertEqual(self.window('2026-10-31 12:00'),
                         ('off', 'Sat 2026-10-31 20:00', 'Sun 2026-11-01 08:00'))


if __name__ == '__main__':
    unittest.main()
