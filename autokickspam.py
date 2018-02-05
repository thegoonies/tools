from __future__ import unicode_literals, absolute_import, print_function, division
import sopel
from sopel.config.types import StaticSection, ValidatedAttribute
from sopel.modules import adminchannel

class AutoKickSection(StaticSection):
    threshold_msg = ValidatedAttribute('threshold_msg', int, default=3)

def configure(config):
    config.define_section('autokick', AutoKickSection)
    config.autokick.configure_setting('threshold_msg', "Auto-kick number of message threshold")
    return

def setup(bot):
    bot.config.define_section('autokick', AutoKickSection)
    bot.memory["autokick-log"] = {}
    return

def clean_phrase(bot, line):
    l = line[:].lower()
    for user in bot.users:
        l = l.replace(user, "")
    # todo: add more sanitizing
    return l

def exceeds_quota(bot, nick, phrase):
    nb_msg_limit = bot.config.autokick.threshold_msg
    nick_log = bot.memory["autokick-log"][nick]
    similar_phrases = [x for x in nick_log if x == phrase]
    if len(similar_phrases) >= (nb_msg_limit-1):
        return True
    return False

@sopel.module.require_privmsg
@sopel.module.require_admin
@sopel.module.priority("high")
@sopel.module.rule("(.*)")
def autokick(bot, trigger, found_match=None):
    sender = trigger.nick
    match = found_match or trigger
    new_phrase = match.group(1)
    cleaned_phrase = clean_phrase(bot, new_phrase)

    if not sender in bot.memory["autokick-log"]:
        bot.memory["autokick-log"][sender] = []

    if exceeds_quota(bot, sender, cleaned_phrase):
        bot.say("Autokicking '{}' for exceeding spam quota...".format(sender))
        adminchannel.kickban(bot, trigger)
        del bot.memory["autokick-log"][sender]
    else:
        bot.memory["autokick-log"][sender].append(cleaned_phrase)
    return

@sopel.module.require_privmsg
@sopel.module.require_admin
@sopel.module.priority("high")
@sopel.module.commands("autoban-reset")
def reset(bot, trigger):
    bot.memory["autokick-log"] = {}
    return
