#!/usr/bin/env python3
import sys
inst_text = open("stage1-opcodes.txt", "r").read().splitlines()
out = open("tms-autogen.sinc", "w")

opmask_to_filter = {
    '0xffe0ffff': lambda a: f"top11=0x{(a & 0xFFE00000) >> 21:x} & src=0x{(a & 0xFFFF):x}",
    '0xffe00000': lambda a: f"top11=0x{(a & 0xFFE00000) >> 21:x}",
    '0xfe000000': lambda a: f"top7=0x{(a & 0xFE000000) >> 25:x}",
    '0xfe200000': lambda a: f"top7=0x{(a & 0xFE000000) >> 25:x} & bit21=0x{(a & 0x200000) >> 21:x}",
    '0xffffffff': lambda a: f"whole=0x{a:x}",
    '0xf0600000': lambda a: f"top4=0x{(a & 0xF0000000) >> 28:x} & bits21and22=0x{(a & 0x600000) >> 21:x}",
    '0xff000000': lambda a: f"top8=0x{(a & 0xFF000000) >> 24:x}",
    '0xffff0000': lambda a: f"top16=0x{(a & 0xFFFF0000) >> 16:x}"
}

specified_patterns = set()

arg_names={
    "*": "indirect_0_15",
    "#": "directLDP_0_15",
    "@": "direct_0_15",
    "A": "addr_reg_22_24",
    "B": "abs_uint_0_23",
    "C": "indir_0_7",
    "E": "reg_0_7",
    "e": "reg_to11_0_7",
    "F": "shortfloat_immed_0_7",
    "G": "reg_8_15",
    "g": "reg_to11_8_15",
    "H": "reg_to7_16_18",
    "I": "indir_no_disp_0_7",
    "i": "indir_enh_0_7",
    "J": "indir_no_disp_8_15",
    "j": "indir_no_disp_enh",
    "K": "reg_19_21",
    "L": "reg_22_24",
    "M": "reg_2_or_3_22",
    "N": "reg_0_or_1_23",
    "O": "indir_8_15",
    "P": "pc_rel_disp_0_15",
    "Q": "reg_0_15",
    "q": "reg_to11_0_15",
    "R": "reg_16_20",
    "r": "reg_to11_16_20",
    "S": "short_int_immed_0_15",
    "U": "uint_0_15",
    "V": "vect_0_4"
}

cond_mnemonic_to_value={
  "u":    0x00,
  "lo":  0x01,
  "ls":   0x02,
  "hi":   0x03,
  "hs":  0x04,
  "eq":  0x05,
  "ne":  0x06,
  "lt":  0x07,
  "le":   0x08,
  "gt":  0x09,
  "ge":  0x0a,
  "unknown":   0x0b,
  "nv":   0x0c,
  "v":    0x0d,
  "nuf":  0x0e,
  "uf":   0x0f,
  "nlv":  0x10,
  "lv":   0x11,
  "nluf": 0x12,
  "luf":  0x13,
  "zuf":  0x14
}

def parse_instructions():
    instructions = []

    for inst in inst_text:
        name, opmask, opcode, args, oplevel = inst.split("\t")
        if int(oplevel) > 1: continue # tms320C3x

        cond_type = ''
        cond_inst = False
        if 'B' in inst:
            cond_inst = True
            cond_type = 'B'
        elif 'C' in inst:
            cond_inst = True
            cond_type = 'C'
        
        if cond_inst:
            conditional_list = list(cond_mnemonic_to_value.keys())
        else:
            conditional_list = [""]

        for cond in conditional_list:
            name_with_cond = name.replace(cond_type, cond)
            
            inst_specifier = opmask_to_filter[opmask](int(opcode,16))
            argument_specifiers = []
            for arg in args:
                if arg in (',', ';', '|'): continue
                arg_name = arg_names[arg]
                argument_specifiers += [arg_name]

            instructions += [{
                'name': name_with_cond,
                'orig_name': name,
                'cond': cond,
                'cond_type': cond_type,
                'is_conditional': cond_inst,
                'inst_specifiers': inst_specifier,
                'argument_specifiers': argument_specifiers,
            }]
    return instructions

instructions = parse_instructions()

argument_specifier_replacements = {
    "pc_rel_disp_0_15": "prel15", # defined as macro, PC relative 16 bits, should really be prel15
    "abs_uint_0_23" : "imm23_pc",
    "direct_0_15": "direct_addr"
}

# state in case the condition is false
# note that these are inverted as in "skip this instruction if..."
condition_false_state={
  "u":   '', # skip check
  "lo":  '!c',
  "ls":   '!c & !z',
  "hi":   'c | z',
  "hs":  'c',
  "eq":  '!z',
  "ne":  'z',
  "lt":  '!n',
  "le":   '!n & !z',
  "gt":  'n | z',
  "ge":  'n',
  "unknown":   '',
  "nv":   'v',
  "v":    '!v',
  "nuf":  'uf',
  "uf":   '!uf',
  "nlv":  'lv',
  "lv":   '!lv',
  "nluf": 'luf',
  "luf":  '!luf',
  "zuf":  '!z & !uf'
}

full_implemented = 0
partial_implemented = 0
total = 0

for inst in instructions:
    name = inst['name']
    inst_specifier = inst['inst_specifiers']
    orig_name = inst['orig_name']
    cond = inst['cond']
    cond_type = inst['cond_type']
    argument_specifiers = inst['argument_specifiers']
    is_conditional = inst['is_conditional']

    # replace anything that's defined in argument_specifier_replacements
    argument_specifiers = [
        argument_specifier_replacements.get(spec, spec) for spec in argument_specifiers
    ]

    # create a copy (otherwise it'd be pass by reference)
    argument_specifiers_ands = list(argument_specifiers)

    # build comma separated list of all instruction arguments
    argument_spec = (", ").join(argument_specifiers)

    # if it's conditional, add the condition to the decoding
    if cond_type == 'B':    
        argument_specifiers_ands += [f"cond_16_20=0x{cond_mnemonic_to_value[cond]:x}"]
    elif cond_type == 'C':
        argument_specifiers_ands += [f"cond_23_27=0x{cond_mnemonic_to_value[cond]:x}"]
    
    # build a list of all instruction arguments with & to specify them
    # even if not decoded during disassembly
    argument_spec_ands = (" & ").join(argument_specifiers_ands)
    
    # if we have extra ands, put an & before them
    if argument_spec_ands:
        argument_spec_ands = "& " + argument_spec_ands
    
    #############

    num = len(argument_specifiers)
    if num == 0:
        src = None
        dst = None
    elif num == 1:
        src = [argument_specifiers[0]]
        dst = None
    elif num > 1:
        src = argument_specifiers[0:-1]
        dst = argument_specifiers[-1]

    #############
    instruction_fully_implemented = False
    # now build the p-code
    pcode = ""

    if is_conditional:
        condition_expr = condition_false_state[cond]
        if condition_expr:
            pcode += f"    if ({condition_expr}) goto inst_next;"

    if orig_name == 'and' and num == 2:
        pcode += f"    {dst} = {dst} & {src[0]};\n"
        instruction_fully_implemented = True

    if orig_name == 'or' and num == 2:
        pcode += f"    {dst} = {dst} | {src[0]};\n"
        instruction_fully_implemented = True

    if orig_name == 'and' and num == 3:
        pcode += f"    {dst} = {src[0]} & {src[1]};\n"
        instruction_fully_implemented = True

    if orig_name == 'or' and num == 3:
        pcode += f"    {dst} = {src[0]} | {src[1]};\n"
        instruction_fully_implemented = True
    
    if orig_name in ('bB', 'br') and 'prel15' in argument_specifiers:
        pcode += """    goto prel15;"""
        instruction_fully_implemented = True
    
    if orig_name in ('ldi', 'ldiC') and 'short_int_immed_0_15' in argument_specifiers:
        pcode += f"""    {dst} = {src[0]};\n"""
        instruction_fully_implemented = True

    #

    if orig_name in ('ldi', 'ldiC') and 'direct_addr' in argument_specifiers:
        #argument_spec += ", DP "
        pcode += f"""    
        {dst} = *({src[0]});\n
        
        """
        instruction_fully_implemented = True
    
    if orig_name == 'ldp' and 'directLDP_0_15' in argument_specifiers:
        pcode += f"""    DP = {src[0]};\n"""
        instruction_fully_implemented = True

    if orig_name in ('call', 'callB') and 'imm23_pc' in argument_specifiers:
        pcode += """
    SP = SP+4;
    *:4 SP = inst_next;
    tmp:4 = imm23_pc;
    goto [tmp];"""
        instruction_fully_implemented = True
    
    if orig_name in ('rets', 'retsB'):
        pcode += """
    SP = SP-4;
    tmp:4 = *:4 SP;
    return [tmp];"""


    
    # count instructions marked as implemented
    total += 1
    if instruction_fully_implemented:
        full_implemented += 1
    if pcode:
        partial_implemented += 1
    
    # write out to file
    out.write( \
f"""
:{name} {argument_spec} is {inst_specifier} {argument_spec_ands} {{
{pcode}
}}\n""")

print(f"Instructions implemented: {full_implemented}/{total}")
print(f"Instructions partially implemented: {partial_implemented}/{total}")

out.close()