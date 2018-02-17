from datetime import datetime, timezone
from textwrap import wrap

import pytz
import urllib.request
import json
import re
import os


from sopel import module
from sopel.config.types import StaticSection, ValidatedAttribute

from terminaltables import AsciiTable


"""
See https://ctftime.org/api/ for more info.
"""

CTFTIME_API_EVENTS_URL = "https://ctftime.org/api/v1/events/"
CTFTIME_API_TOP10_URL  = "https://ctftime.org/api/v1/top/"
CTFTIME_API_TEAMS_URL  = "https://ctftime.org/api/v1/teams/"

TIMEZONE_FILE = os.getenv("HOME") + "/timezones.txt"
VALID_TIMEZONES_FILE = os.getenv("HOME") + "/valid_timezones.txt"

class CtfTimeSection(StaticSection):
    timezone_file = FilenameAttribute('timezone_file', directory=True, default=TIMEZONE_FILE)
    valid_timezone_file = FilenameAttribute('valid_timezone_file', directory=True, default=VALID_TIMEZONES_FILE)

def configure(config):
    config.define_section('ctftime', CtfTimeSection, validate=False)
    config.ctftime.configure_setting('timezone_file','Path to timezone file that holds the currently defined timezones to display')
    config.ctftime.configure_setting('valid_timezone_file','Path to timezone file')
    return

def setup(bot):
    bot.config.define_section('ctftime', CtfTimeSection)
    return

def get_http_data(url):
    req = urllib.request.Request(url)
    req.add_header('User-Agent', 'Mozilla/5.0')
    fd = urllib.request.urlopen(req)
    return fd.read().decode('utf-8')


def get_http_json(url):
    raw_data = get_http_data(url)
    return json.loads( raw_data )


def convert_ctftime_datetime(dt):
    date_fmt = "%Y-%m-%dT%X%z"
    date = re.sub(r"([\+-])(\d{2}):(\d{2})", r"\1\2\3", dt)
    return datetime.strptime(date, date_fmt)


def now(dt=timezone.utc):
    return datetime.now(dt)


@module.rule('(hello|hi|hey)!?')
def hi(bot, trigger):
    bot.say("Hi {}, how are you?".format(trigger.nick))
    return


@module.commands('next')
def next_ctf_time(bot, trigger):
    n = trigger.group(2) or 5
    n = int(n)
    try:
        js = get_http_json(CTFTIME_API_EVENTS_URL)
    except Exception as e:
        bot.say("Cannot get '{}', got: {}".format(CTFTIME_API_EVENTS_URL, str(e) ))
        return

    i = 0
    bot.say("The next {} CTF are:".format( min(n,len(js))))

    table_data = [
        ['#', 'CTF', 'Start', 'Finish', 'Duration', 'On-Site'],
    ]

    while i < n:
        line = []

        # number
        line.append("{:d}".format(js[i]["id"]))

        # ctf name
        line.append(js[i]["title"])

        # times (start / finish)
        dt_start = convert_ctftime_datetime(js[i]["start"])
        dt_end = convert_ctftime_datetime(js[i]["finish"])
        dt_now = now()

        m = "in "
        dt_delta = dt_start - dt_now
        if dt_delta.days == 0:
            m+= "{} hours".format(dt_delta.seconds//3600)
        else:
            m+= "{} days".format(dt_delta.days)

        date_fmt = "%d/%m/%y %H:%M"
        start_time = dt_start.strftime(date_fmt)
        finish_time = dt_end.strftime(date_fmt)
        line.append("{} ({})".format(start_time, m))
        line.append(finish_time)

        # duration
        days = js[i]["duration"]["days"]
        hours = js[i]["duration"]["hours"]
        m = ""
        if days != 0:
            m+= "{} days ".format(days)
        if hours != 0:
            m+= "{} hours".format(hours)
        line.append(m)

        # is_onsite
        line.append(str(js[i]["onsite"]))

        table_data.append(line)
        i += 1

    for _ in AsciiTable(table_data).table.splitlines():
        bot.say(_)
    return


def print_team_info(bot, team_id):
    team = get_http_json("{:s}{:d}/".format(CTFTIME_API_TEAMS_URL, team_id))
    bot.reply("Team '{}' (id={:d}) from {}:".format(team["name"], team["id"], team["country"]))
    for entry in team["rating"]:
        for year in entry.keys():
            score= entry[year]["rating_points"]
            rank = entry[year]["rating_place"]
            bot.say("[{}] Rank {} (score={})".format(year, rank, score))
    return


@module.commands('team')
@module.exmaple('team thegoonies')
def get_team_info(bot, trigger):
    team_name = trigger.group(2)
    if not team_name:
        bot.reply("Missing team name")
        return

    try:
        js = get_http_json(CTFTIME_API_TEAMS_URL)
    except Exception as e:
        bot.reply("Cannot get '{}', got: {}".format(CTFTIME_API_TEAMS_URL, str(e) ))
        return

    for entry in js:
        if entry["name"] == team_name or team_name in entry["aliases"]:
            return print_team_info(bot, entry["id"])

    bot.reply("No team '{}' found".format(team_name))
    return


@module.commands("ctf-info")
@module.example(".ctf-info 1337")
def show_ctf_info(bot, trigger):
    ctf_id = trigger.group(2)
    if not ctf_id or not ctf_id.isdigit():
        bot.reply("Missing/Incorrect CTF event id")
        return

    ctf_id = int(ctf_id)
    try:
        js = get_http_json("{}{}/".format(CTFTIME_API_EVENTS_URL, ctf_id))
    except Exception as e:
        bot.reply("Cannot get '{}', got: {}".format(CTFTIME_API_EVENTS_URL, str(e) ))
        return

    table_data = []

    table_data.append(["Name", js["title"]])
    table_data.append(["URL", js["url"]])
    table_data.append(["Description", '\n'.join(wrap(js["description"], 80)) ])
    table_data.append(["Format", js["format"]])
    table_data.append(["Location", js["location"]])
    table_data.append(["On-site CTF?", str(js["onsite"])])

    dt_fmt = "%A %d %B %Y - %H:%M:%S %Z"
    dt_start = convert_ctftime_datetime(js["start"])
    dt_now = now()
    if dt_now <= dt_start:
        delta = dt_start-dt_now
        table_data.append(["Start time", "{} ({} hours from now)".format(dt_start.strftime(dt_fmt),
                                                                        delta.seconds//3600 + delta.days*24)])
    else:
        table_data.append(["Start time", "{}".format(dt_start.strftime(dt_fmt))])

    dt_end = convert_ctftime_datetime(js["finish"])
    table_data.append(["Finish", "{}".format(dt_end.strftime(dt_fmt))])

    table = AsciiTable(table_data)
    table.title = "Information for CTF #{}".format(ctf_id)
    table.inner_heading_row_border = False
    for _ in table.table.splitlines():
        bot.say(_)

    return


@module.commands("ctf-search")
@module.example(".ctf-search defcon")
def search_ctf_by_title(bot, trigger):
    pattern = trigger.group(2)
    if not pattern or len(pattern.strip())==0:
        bot.reply("Missing/Incorrect pattern to look up for")
        return

    pattern = pattern.strip().lower()
    try:
        url = "{}?start={}&finish={}&limit={}".format(CTFTIME_API_EVENTS_URL, 0, 1000000000000000000, 10000000000)
        js = get_http_json(url)
    except Exception as e:
        bot.reply("Cannot get '{}', got: {}".format(url, str(e) ))
        return

    table_data = [
        ['Id', 'CTF', 'Start', 'Finish'],
    ]

    found = False
    for item in js:
        if pattern not in item["title"].lower(): continue
        dt_fmt = "%Y/%m/%d"
        dt_start = convert_ctftime_datetime(item["start"]).strftime(dt_fmt)
        dt_end = convert_ctftime_datetime(item["finish"]).strftime(dt_fmt)
        line = [item["id"], item["title"], dt_start, dt_end]
        table_data.append(line)
        found = True

    if not found:
        bot.reply("No match")
    else:
        for _ in AsciiTable(table_data).table.splitlines():
            bot.say(_)

        bot.reply("Use .ctf-info <id> to get more info")
    return


@module.commands("now")
@module.example(".now")
@module.example(".now add Europe/Paris")
@module.example(".now del Europe/Paris")
def timezone_ccommand_handler(bot, trigger):
    arg = trigger.group(2)
    if not arg or len(arg.strip())==0:
        print_utc_datetime(bot, trigger)
        return

    p = arg.split()
    if len(p)!=2:
        bot.reply("Incorrect argument: {}".format(arg))
        return

    action, param = p
    if action == "add":
        add_timezone(bot, trigger, param)
        return

    if action == "del":
        del_timezone(bot, trigger, param)
        return

    bot.reply("Incorrect action: {}".format(action))
    return

def print_utc_datetime(bot, trigger):
    t = now()
    bot.say("All the time information are shown in UTC timezone")
    bot.say("Current UTC time: {}".format(t.strftime("%d/%m/%Y %H:%M:%S %Z")))

    timezone_file = bot.config.ctftime.timezone_file
    if not os.path.isfile(timezone_file):
        return

    timezones = [x.strip() for x in open(timezone_file, "r").readlines() if x.strip()]

    for tz in timezones:
        try:
            local_tz = pytz.timezone(tz)
            local_time = now(local_tz)
            bot.say("Current time for '{}': {}".format(tz, local_time.strftime("%d/%m/%Y %H:%M:%S %Z")))
        except Exception as e:
            print(str(e))
            continue
    return

def add_timezone(bot, trigger, tz_to_add):
    timezone_file = bot.config.ctftime.timezone_file
    valid_timezone_file = bot.config.ctftime.valid_timezone_file

    valid_timezones = [x.strip() for x in open(valid_timezone_file, "r").readlines() if x.strip()]
    if tz_to_add not in valid_timezones:
        bot.reply("'{}' is not a valid timezone".format(tz_to_add))
        return

    with open(timezone_file, "r") as fd:
        timezones = set([x.strip() for x in fd.readlines() if x.strip()])

    with open(timezone_file, "w") as fd:
        timezones.add(tz_to_add)
        fd.write("\n".join(sorted(list(timezones))))
        bot.reply("Added '{}' to timezone file".format(tz_to_add))
    return

def del_timezone(bot, trigger, tz_to_del):
    timezone_file = bot.config.ctftime.timezone_file

    with open(timezone_file, "r") as fd:
        timezones = set([x.strip() for x in fd.readlines() if x.strip()])

    with open(timezone_file, "w") as fd:
        if tz_to_del not in timezones:
            bot.reply("'{}' is not in the timezone file".format(tz_to_del))
        else:
            timezones.discard(tz_to_del)
            fd.write("\n".join(sorted(list(timezones))))
            bot.reply("'{}' is removed from the timezone file".format(tz_to_del))
    return
