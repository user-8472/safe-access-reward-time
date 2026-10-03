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
