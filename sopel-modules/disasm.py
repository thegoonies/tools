# -*- mode: python -*-
# -*- coding: utf-8 -*-

from sopel import module
import capstone

def get_arch_mode(a):
    if a=="x86-16":
        return capstone.CS_ARCH_X86, capstone.CS_MODE_16, capstone.CS_MODE_LITTLE_ENDIAN

    elif a=="x86-32":
        return capstone.CS_ARCH_X86, capstone.CS_MODE_32, capstone.CS_MODE_LITTLE_ENDIAN

    elif a=="x86-64":
        return capstone.CS_ARCH_X86, capstone.CS_MODE_64, capstone.CS_MODE_LITTLE_ENDIAN

    # arm
    elif a=="arm":
        return capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM, capstone.CS_MODE_LITTLE_ENDIAN

    elif a=="arm-thumb":
        return capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB, capstone.CS_MODE_LITTLE_ENDIAN

    # aarch64
    elif a=="aarch64":
        return capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM, capstone.CS_MODE_LITTLE_ENDIAN

    # mips/mips64
    elif a=="mips":
        return capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS32, capstone.CS_MODE_LITTLE_ENDIAN

    elif a=="mipsbe":
        return capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS32, capstone.CS_MODE_BIG_ENDIAN

    elif a=="mips64":
        return capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS64, capstone.CS_MODE_LITTLE_ENDIAN

    elif a=="mips64be":
        return capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS64, capstone.CS_MODE_BIG_ENDIAN

    raise Exception("Unknown")


def disassemble(raw_data, mode):
    arch, mode, endian = get_arch_mode(mode)
    cs = capstone.Cs(arch, mode | endian)
    insns = ["{:s} {:s}".format(i.mnemonic, i.op_str) for i in cs.disasm(bytes(raw_data), 0x4000)]
    return "\n".join(insns)


def disassemble_command(bot, trigger, arch):
    insns = trigger.group(2)
    code = disassemble(bytes.fromhex(insns), arch)
    # bot.reply("Disassembled instructions for '{}'".format(arch))
    bot.say(code.replace("\n", "; "))
    return


@module.commands('disasm-x86')
def disassemble_x86(bot, trigger):
    return disassemble_command(bot, trigger, "x86-64")

@module.commands('disasm-arm')
def disassemble_arm(bot, trigger):
    return disassemble_command(bot, trigger, "arm")

@module.commands('disasm-mips')
def disassemble_mips(bot, trigger):
    return disassemble_command(bot, trigger, "mips")

@module.commands('disasm-aarch64')
def disassemble_aarch64(bot, trigger):
    return disassemble_command(bot, trigger, "aarch64")
