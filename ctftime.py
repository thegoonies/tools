from datetime import datetime
import urllib.request
import json

from sopel import module

"""
See https://ctftime.org/api/ for more info.
"""

CTFTIME_API_EVENTS_URL = "https://ctftime.org/api/v1/events/"
CTFTIME_API_TOP10_URL  = "https://ctftime.org/api/v1/top/"
CTFTIME_API_TEAMS_URL  = "https://ctftime.org/api/v1/teams/"


def get_http_data(url):
    req = urllib.request.Request(url)
    req.add_header('User-Agent', 'Mozilla/5.0')
    fd = urllib.request.urlopen(req)
    return fd.read().decode('utf-8')


def get_http_json(url):
    raw_data = get_http_data(url)
    return json.loads( raw_data )


@module.rule('hello!?')
def hi(bot, trigger):
    bot.say("Hi " + trigger.nick)
    return


def convert_ctftime_datetime(dt):
    date_fmt = "%Y-%m-%dT%X"
    return datetime.strptime(dt.replace("+00:00",""), date_fmt)


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
    date_fmt = "%Y-%m-%dT%X"
    bot.reply("Next {} CTF:".format( min(n,len(js))) )
    while True:
        if i==n:
            break

        msg = ["{:d} -".format(i+1),]
        msg.append(js[i]["title"])
        dt_start = convert_ctftime_datetime(js[i]["start"])
        dt_end = convert_ctftime_datetime(js[i]["finish"])
        dt_now = datetime.now()
        if dt_start < dt_now:
            # if here, the ctf has already started
            dt_delta = dt_end - dt_now
            msg.append("finishes in")
        else:
            dt_delta = dt_start - dt_now
            msg.append("starts in")
        if dt_delta.days == 0:
            msg.append("{} hours {} min".format(dt_delta.seconds/3600, dt_delta.seconds/60))
        else:
            msg.append("{} days".format(dt_delta.days))

        dt_duration = dt_end - dt_start
        msg.append("- duration: {} days, {} hours, {} minutes".format(dt_duration.days, dt_duration.seconds/3600, dt_duration.seconds/60))

        if js[i]["onsite"]==True:
            msg.append("(onsite)")

        bot.reply(" ".join(msg))
        i += 1
    return


def print_team_info(bot, team_id):
    team = get_http_json("{:s}{:d}/".format(CTFTIME_API_TEAMS_URL, team_id))
    bot.reply("Team '{}' (id={:d}) from {}:".format(team["name"], team["id"], team["country"]))
    for entry in team["rating"]:
        for year in entry.keys():
            score= entry[year]["rating_points"]
            rank = entry[year]["rating_place"]
            bot.reply("[{}] Rank {} (score={})".format(year, rank, score))
    return


@module.commands('team')
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

    msg = []
    msg.append("Name: {}".format(js["title"]))
    msg.append("URL: {}".format(js["url"]))
    msg.append("Description: {}".format(js["description"]))
    msg.append("Format: {}".format(js["format"]))
    msg.append("Location: {}".format(js["location"]))
    msg.append("On-site?: {}".format("Yes" if js["onsite"] else "No"))
    msg.append("Start: {}".format(js["start"]))
    msg.append("Finish: {}".format(js["finish"]))
    for _ in msg: bot.reply(_)
    return


@module.commands("ctf-search")
def search_ctf_by_title(bot, trigger):
    pattern = trigger.group(2)
    if not pattern or len(pattern.strip())==0:
        bot.reply("Missing/Incorrect pattern to lookup")
        return

    pattern = pattern.strip().lower()
    try:
        url = "{}?start={}&finish={}&limit={}".format(CTFTIME_API_EVENTS_URL, 0, 1000000000000000000, 10000000000)
        js = get_http_json(url)
    except Exception as e:
        bot.reply("Cannot get '{}', got: {}".format(url, str(e) ))
        return

    found = False
    for item in js:
        if pattern not in item["title"].lower(): continue
        dt_fmt = "%Y/%m/%d"
        dt_start = convert_ctftime_datetime(item["start"]).strftime(dt_fmt)
        dt_end = convert_ctftime_datetime(item["finish"]).strftime(dt_fmt)
        msg = "[{}] {} ({} - {})".format(item["id"], item["title"], dt_start, dt_end)
        bot.reply(msg)
        found = True

    if not found:
        bot.reply("No match")
    else:
        bot.reply("Use .ctf-info <id> to get more info")
    return
