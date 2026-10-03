# Schedule-window logic for Safe Access blocktime rules. Kept separate from
# reward_server.py (and free of its config/web-server imports) so it can be
# unit tested on its own - see tests/test_schedule.py.
import time


MINUTES_PER_WEEK = 7 * 1440


def _schedule_week_minute(weekday, clock):
    # weekday: 0=Sunday; clock: HHMM as an int, 2400 meaning end of day.
    return weekday * 1440 + (clock // 100) * 60 + clock % 100


def get_schedule_window(conn, profile_id, now):
    # Safe Access blocktime rows (schedule.type = 3) are the *blocked* periods,
    # in router-local time. Returns (state, window_start, window_end): state is
    # 'off' (blocked now; the window is the next allowed period), 'on' (allowed
    # now; the window is the current allowed period, so its start may be in the
    # past), or 'always_off'/'always_on' (window values None).
    rows = conn.execute(
        "SELECT begin_weekday, begin_clock, end_weekday, end_clock "
        "FROM schedule WHERE profile_id = ? AND type = 3",
        (profile_id,)
    ).fetchall()
    blocks = []
    for bw, bc, ew, ec in rows:
        start = _schedule_week_minute(bw, bc)
        end = _schedule_week_minute(ew, ec)
        if end <= start:
            end += MINUTES_PER_WEEK
        # Lay out over three consecutive weeks so a block that wraps past
        # Saturday night (or the merge across it) is seen contiguously.
        for week in (-1, 0, 1):
            blocks.append((start + week * MINUTES_PER_WEEK, end + week * MINUTES_PER_WEEK))
    if not blocks:
        return 'always_on', None, None
    blocks.sort()
    merged = [list(blocks[0])]
    for start, end in blocks[1:]:
        if start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    if any(end - start >= MINUTES_PER_WEEK for start, end in merged):
        return 'always_off', None, None

    lt = time.localtime(now)
    now_minute = ((lt.tm_wday + 1) % 7) * 1440 + lt.tm_hour * 60 + lt.tm_min
    # The allowed windows are the gaps between merged blocks. The copies laid
    # out a week either side guarantee a block before now and after the next gap.
    for i, (start, end) in enumerate(merged):
        if start <= now_minute < end:
            state, window = 'off', (end, merged[i + 1][0])
            break
        if start > now_minute:
            state, window = 'on', (merged[i - 1][1], start)
            break
    # Build from this week's Sunday midnight; mktime normalizes the overflowing
    # (or negative) minute field into the right local date, DST included.
    sunday_mday = lt.tm_mday - (lt.tm_wday + 1) % 7
    window_start, window_end = [
        int(time.mktime((lt.tm_year, lt.tm_mon, sunday_mday, 0, minute, 0, 0, 0, -1)))
        for minute in window]
    return state, window_start, window_end


# --- Schedule editing: allowed ("on") windows per day <-> blocked periods ---
# The editor works in allowed windows, which is how people think about a
# schedule ("6:00 AM - 9:00 PM"); Safe Access stores blocked periods. A day
# is a list of [start, end] minute pairs within that day (0-1440); day 0 is
# Sunday.

def on_windows_from_blocks(blocks):
    # blocks: iterable of (begin_weekday, begin_clock, end_weekday, end_clock),
    # which may cross midnight or wrap from Saturday into Sunday.
    blocked = []
    for bw, bc, ew, ec in blocks:
        start = _schedule_week_minute(bw, bc)
        end = _schedule_week_minute(ew, ec)
        if end <= start:
            end += MINUTES_PER_WEEK
        if end > MINUTES_PER_WEEK:  # wraps past Saturday night: split it
            blocked.append((start, MINUTES_PER_WEEK))
            blocked.append((0, end - MINUTES_PER_WEEK))
        else:
            blocked.append((start, end))
    blocked.sort()
    days = [[] for _ in range(7)]
    position = 0
    for start, end in blocked + [(MINUTES_PER_WEEK, MINUTES_PER_WEEK)]:
        if start > position:
            # An allowed gap - split it at each midnight it spans.
            gap_start = position
            while gap_start < start:
                day = gap_start // 1440
                day_end = min(start, (day + 1) * 1440)
                days[day].append([gap_start - day * 1440, day_end - day * 1440])
                gap_start = day_end
        position = max(position, end)
    return days


def blocks_from_on_windows(days):
    # Inverse of on_windows_from_blocks: same-day blocked periods, as the
    # Safe Access API takes them. A fully allowed day has no blocks.
    blocks = []
    for weekday, windows in enumerate(days):
        position = 0
        for start, end in sorted(windows) + [[1440, 1440]]:
            if start > position:
                blocks.append({'begin_weekday': weekday, 'begin_clock': _clock(position),
                               'end_weekday': weekday, 'end_clock': _clock(start)})
            position = max(position, end)
    return blocks


def _clock(minute):
    return (minute // 60) * 100 + minute % 60


def validate_on_windows(days):
    # Raises ValueError unless days is 7 lists of non-overlapping
    # [start, end] minute pairs with 0 <= start < end <= 1440.
    if not isinstance(days, list) or len(days) != 7:
        raise ValueError('expected 7 days')
    for windows in days:
        if not isinstance(windows, list) or len(windows) > 12:
            raise ValueError('bad day')
        previous_end = -1
        for window in sorted(windows):
            if (not isinstance(window, list) or len(window) != 2
                    or not all(isinstance(m, int) and not isinstance(m, bool) for m in window)):
                raise ValueError('bad window')
            start, end = window
            if not (0 <= start < end <= 1440) or start < previous_end:
                raise ValueError('windows must be within the day and not overlap')
            previous_end = end
