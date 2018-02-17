import re, os, datetime

from sopel import module
from sopel.config.types import StaticSection, ValidatedAttribute, FilenameAttribute

DEFAULT_CHANLOGS_DIR = os.getenv("HOME") + "/chanlogs"
DEFAULT_LINE_PATTERN = re.compile(r"^([^\s]*)  <([^>]*)> (.*)$")


class GrepLogsSection(StaticSection):
    dir = FilenameAttribute('dir', directory=True, default=DEFAULT_CHANLOGS_DIR)


def configure(config):
    config.define_section('greplogs', GrepLogsSection, validate=False)
    config.greplogs.configure_setting('dir','Path to channel log storage directory')
    return


def setup(bot):
    bot.config.define_section('greplogs', GrepLogsSection)
    return


def get_log_files_for_channel(dpath, name):
    for fname in os.listdir(dpath):
        if not fname.startswith(name):
            continue

        fpath = "{}/{}".format(dpath, fname)
        if not os.access(fpath, os.R_OK):
            continue

        yield fpath
    return


def parse_logline(bot, line):
    # in log file, pattern always is
    # date  <nick> msg
    date, nick, msg = [x.strip() for x in re.split(DEFAULT_LINE_PATTERN, line) if len(x.strip()) ]
    date = date.replace("+00:00", "+0000")
    date_obj = datetime.datetime.strptime(date, "%Y-%m-%dT%H:%M:%S%z")
    return (date_obj, nick, msg)


@module.commands("grep-logs")
@module.example(".grep-logs http(s)?://")
def grep_logs(bot, trigger):
    pattern_str = trigger.group(2)
    if not pattern_str:
        bot.reply("Missing pattern")
        return

    pattern = re.compile(pattern_str, re.IGNORECASE)
    dpath = bot.config.greplogs.dir
    channel_name = trigger.sender
    found = 0

    for log_file in get_log_files_for_channel(dpath, channel_name):
        with open(log_file, "r") as f:
            for i, line in enumerate(f.readlines()):
                try:
                    date, nick, msg = parse_logline(bot, line)
                    if pattern.search(msg):
                        bot.say("On {}, {} said: {}".format(date.strftime("%c"), nick, msg))
                        found += 1

                except Exception as e:
                    continue

    if found == 0:
        bot.reply("No entries found matching '{}'".format(pattern_str))
    else:
        bot.reply("Found {} entr{} matching '{}'".format(found,
                                                         "ies" if found > 1 else "y",
                                                         pattern_str))
    return
