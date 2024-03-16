#!/usr/bin/env python3
import sys
inst_text = sys.stdin.read().splitlines()

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

branches={
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

for inst in inst_text:
    name, opmask, opcode, args, oplevel = inst.split("\t")
    if int(oplevel) > 1: continue # TODO: what oplevel do we want?

    cond_char = ''
    cond_inst = False
    if 'B' in inst:
        cond_inst = True
        cond_char = 'B'
    elif 'C' in inst:
        cond_inst = True
        cond_char = 'C'
    
    if cond_inst:
        conditional_list = list(branches.keys())
    else:
        conditional_list = [""]

    for cond in conditional_list:
        cond_name = name.replace(cond_char, cond)
        if cond_inst: print(f"{cond}, {cond_name}", file=sys.stderr)
        inst_specifier = opmask_to_filter[opmask](int(opcode,16))
        reg_specifiers = []
        reg_specifiers_ands = []
        for arg in args:
            if arg in (',', ';', '|'): continue
            arg_name = arg_names[arg]
            reg_specifiers += [arg_name]
            reg_specifiers_ands += [arg_name]
            
            ARG_FILTER=""
        
        if cond_char == 'B':
            reg_specifiers_ands += [f"cond_16_20=0x{branches[cond]:x}"]
        elif cond_char == 'C':
            reg_specifiers_ands += [f"cond_23_27=0x{branches[cond]:x}"]
        
        reg_spec = (", ").join(reg_specifiers)
        reg_spec_ands = (" & ").join(reg_specifiers_ands)
        if reg_spec_ands: reg_spec_ands = "& " + reg_spec_ands

        if (reg_spec, inst_specifier, reg_spec_ands) in specified_patterns:
            print(f"Skipping duplicate {cond_name}", file=sys.stderr)
            continue
        
        specified_patterns.add((reg_spec, inst_specifier))

        print( \
f"""
:{cond_name} {reg_spec} is {inst_specifier} {reg_spec_ands} {{

}}""")

