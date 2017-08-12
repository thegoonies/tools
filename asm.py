# -*- mode: python -*-
# -*- coding: utf-8 -*-

from sopel import module
import keystone


def get_arch_mode(lib, a):
    if a=="x86-16":
        if lib=="keystone":      arch, mode, endian = keystone.KS_ARCH_X86, keystone.KS_MODE_16, keystone.KS_MODE_LITTLE_ENDIAN
        elif lib=="capstone":    arch, mode, endian = capstone.CS_ARCH_X86, capstone.CS_MODE_16, capstone.CS_MODE_LITTLE_ENDIAN
        else:                    raise Exception("Invalid")

    elif a=="x86-32":
        if lib=="keystone":     arch, mode, endian = keystone.KS_ARCH_X86, keystone.KS_MODE_32, keystone.KS_MODE_LITTLE_ENDIAN
        elif lib=="capstone":   arch, mode, endian = capstone.CS_ARCH_X86, capstone.CS_MODE_32, capstone.CS_MODE_LITTLE_ENDIAN
        else:                   raise Exception("Invalid")

    elif a=="x86-64":
        if lib=="keystone":     arch, mode, endian = keystone.KS_ARCH_X86, keystone.KS_MODE_64, keystone.KS_MODE_LITTLE_ENDIAN
        elif lib=="capstone":   arch, mode, endian = capstone.CS_ARCH_X86, capstone.CS_MODE_64, capstone.CS_MODE_LITTLE_ENDIAN
        else:                   raise Exception("Invalid")

    # arm
    elif a=="arm":
        if lib=="keystone":     arch, mode, endian = keystone.KS_ARCH_ARM, keystone.KS_MODE_ARM, keystone.KS_MODE_LITTLE_ENDIAN
        elif lib=="capstone":   arch, mode, endian = capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM, capstone.CS_MODE_LITTLE_ENDIAN
        else:                   raise Exception("Invalid")

    elif a=="arm-thumb":
        if lib=="keystone":     arch, mode, endian = keystone.KS_ARCH_ARM, keystone.KS_MODE_THUMB, keystone.KS_MODE_LITTLE_ENDIAN
        elif lib=="capstone":   arch, mode, endian = capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB, capstone.CS_MODE_LITTLE_ENDIAN
        else:                   raise Exception("Invalid")

    # aarch64
    elif a=="aarch64":
        if lib=="keystone":     arch, mode, endian = keystone.KS_ARCH_ARM64, 0, keystone.KS_MODE_LITTLE_ENDIAN
        elif lib=="capstone":   arch, mode, endian = capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM, capstone.CS_MODE_LITTLE_ENDIAN
        else:                   raise Exception("Invalid")

    # mips/mips64
    elif a=="mips":
        if lib=="keystone":     arch, mode, endian = keystone.KS_ARCH_MIPS, keystone.KS_MODE_MIPS32, keystone.KS_MODE_LITTLE_ENDIAN
        elif lib=="capstone":   arch, mode, endian = capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS32, capstone.CS_MODE_LITTLE_ENDIAN
        else:                   raise Exception("Invalid")

    elif a=="mipsbe":
        if lib=="keystone":     arch, mode, endian = keystone.KS_ARCH_MIPS, keystone.KS_MODE_MIPS32, keystone.KS_MODE_BIG_ENDIAN
        elif lib=="capstone":   arch, mode, endian = capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS32, capstone.CS_MODE_BIG_ENDIAN
        else:                   raise Exception("Invalid")

    elif a=="mips64":
        if lib=="keystone":     arch, mode, endian = keystone.KS_ARCH_MIPS, keystone.KS_MODE_MIPS64, keystone.KS_MODE_LITTLE_ENDIAN
        elif lib=="capstone":   arch, mode, endian = capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS64, capstone.CS_MODE_LITTLE_ENDIAN
        else:                   raise Exception("Invalid")

    elif a=="mips64be":
        if lib=="keystone":     arch, mode, endian = keystone.KS_ARCH_MIPS, keystone.KS_MODE_MIPS64, keystone.KS_MODE_BIG_ENDIAN
        elif lib=="capstone":   arch, mode, endian = capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS64, capstone.CS_MODE_BIG_ENDIAN
        else:                   raise Exception("Invalid")

    return arch, mode, endian


def assemble(asm_code, mode):
    try:
        arch, mode, endian = get_arch_mode("keystone", mode)
        ks = keystone.Ks(arch, mode | endian)
        code, cnt = ks.asm(asm_code)
        if cnt==0:
            code = b""
            code = bytes(bytearray(code))
    except Exception:
        code, cnt = (b"", -1)
    return (code, cnt)


def assemble_command(bot, trigger, arch):
    insns = trigger.group(2)
    code, cnt = assemble(insns, arch)
    if cnt==-1:
        bot.reply("Failed to assemble")
        return

    if cnt==0:
        bot.reply("No valid instruction")
        return

    res = bytes(code).hex()
    bot.reply("Assembled {} instructions for '{}': {:d} bytes".format(cnt, arch, len(res)//2))
    bot.say(res)
    return


@module.commands('asm-x86')
def assemble_x86(bot, trigger):
    return assemble_command(bot, trigger, "x86-64")

@module.commands('asm-arm')
def assemble_arm(bot, trigger):
    return assemble_command(bot, trigger, "arm")

@module.commands('asm-aarch64')
def assemble_aarch64(bot, trigger):
    return assemble_command(bot, trigger, "aarch64")

@module.commands('asm-mips')
def assemble_mips(bot, trigger):
    return assemble_command(bot, trigger, "mips")

@module.commands('asm-sparc')
def assemble_sparc(bot, trigger):
    return assemble_command(bot, trigger, "sparc")
