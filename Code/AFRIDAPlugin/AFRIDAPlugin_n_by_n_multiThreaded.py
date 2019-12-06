from idautils import *
from idaapi import *
from idc import *
import json
import threading
import scipy.io
import idautils
import time
import os

# Tested on IDA 6.8 Python x64 2.7

# =========== Configurations ===========


release_library = 'I:\\Final Project\\Libraries\\uclibc_release\\libuClibc-1.0.28.so'
debug_library = 'I:\\Final Project\\Libraries\\uclibc_debug\\libuClibc-1.0.28.so'
base = 'C:\/Users\User\/Desktop\/Final Project\/Statistics\/'  # 'I:\/Final Project\/Statistics\/'
function_min_size = 10

# =========== global vars ===========


file_index = 0
max_enum = 0
max_feature_enum = 0
threadLock_logfile = threading.Lock()
threadLock_grades = threading.Lock()
index = 0
enum_map = {}
enum_features_map = {}
features = {
    'Nested function', 'Jump match', 'Constant match',
            'Command rare match', 'Mnemonic match', 'Mnemonic subsequence match',
            'Amount of menemonic match', 'Number of args match'
            }


# =========== Utilities ===========


def json_read(file):
    with open(file) as json_file:
        data = json.load(json_file)
    return data


def json_write(file, data):
    with open(file, 'w') as json_file:
        json.dump(data, json_file)


def json_append(file, data):
    threadLock_grades.acquire()
    try:
        if not os.path.isfile(file):
            feeds = {}
        else:
            feedsjson = open(file, "r")
            feeds = json.load(feedsjson)
            feedsjson.flush()
            feedsjson.close()

        feeds.update(data)
        f = open(file, 'w')
        f.write(json.dumps(feeds, indent=2))
        f.flush()
        f.close()
    except Exception as e:
        print "Exeption: " + e
    threadLock_grades.release()


def get_ea_start_func(adderess):
    func = get_func(adderess)
    return func.startEA


def log(file, data):
    with open(file, "a") as log_file:
        log_file.write(data)


# =========== Mnemonic match ===========


def get_func_mnemonic_list(i_start_func):
    mnemonics_container = []

    func_instructions = FuncItems(i_start_func)

    for instruction in func_instructions:
        menomonic = GetMnem(instruction)
        if menomonic not in mnemonics_container:
            mnemonics_container += [menomonic]

    return mnemonics_container


def mnemonic_match_feature(i_start_debug_func, i_start_release_func):
    debug_mnemonics_list = get_func_mnemonic_list(i_start_debug_func)
    release_mnemonics_list = get_func_mnemonic_list(i_start_release_func)

    amount_of_containment = 0

    for debug_mnemonics in debug_mnemonics_list:
        if debug_mnemonics in release_mnemonics_list:
            amount_of_containment += 1

    return amount_of_containment / float(len(release_mnemonics_list))


def mnemonic_match_feaure_helper(i_debug_mnemonics_list, i_release_mnemonics_list):
    amount_of_containment = 0

    for debug_mnemonics in i_debug_mnemonics_list:
        if debug_mnemonics in i_release_mnemonics_list:
            amount_of_containment += 1

    if len(i_release_mnemonics_list) == 0 and amount_of_containment == 0:
        return 1
    if len(i_release_mnemonics_list) == 0:
        return 0

    return amount_of_containment / float(len(i_release_mnemonics_list))


# =========== Command rare match ===========


def get_rare_mnemonic_list(i_mnemonics_dictionary):
    rare_mnemonic_list = []

    for mnemonic in i_mnemonics_dictionary.keys():
        if i_mnemonics_dictionary[mnemonic] == 1:
            rare_mnemonic_list += [mnemonic]

    return rare_mnemonic_list


def get_mnemonic_dictionary(i_start_func):
    func_instructions = FuncItems(i_start_func)
    mnemonics_dictionary = {}

    for instruction in func_instructions:
        mnemonic = GetMnem(instruction)
        if mnemonic not in mnemonics_dictionary:
            mnemonics_dictionary[mnemonic] = 1
        else:
            mnemonics_dictionary[mnemonic] += 1

    return mnemonics_dictionary


def get_rare_instruction_list(i_start_func):
    rare_commands_list = []

    mnemonic_dictionary = get_mnemonic_dictionary(i_start_func)
    rare_mnemonic_list = get_rare_mnemonic_list(mnemonic_dictionary)

    func_instructions = FuncItems(i_start_func)

    for instruction in func_instructions:
        mnemonic = GetMnem(instruction)
        if mnemonic in rare_mnemonic_list:
            disasm = GetDisasm(instruction).split(";")
            rare_commands_list += [disasm[0]]

    return rare_commands_list


def get_instructions_list(i_start_func):
    commands_list = []

    func_instructions = FuncItems(i_start_func)
    for instruction in func_instructions:
        instruction = GetDisasm(instruction).split(";")
        commands_list += [instruction[0]]

    return commands_list


def rare_commands_feature(i_start_debug_func, i_start_release_func):
    rare_release_instruction_list = get_rare_instruction_list(i_start_release_func)
    debug_instruction_list = get_instructions_list(i_start_debug_func)

    rare_command_in_release_exist_in_debug = 0

    for release_command in rare_release_instruction_list:
        if release_command in debug_instruction_list:
            rare_command_in_release_exist_in_debug += 1

    return rare_command_in_release_exist_in_debug / float(len(rare_release_instruction_list))


def rare_commands_feature_helper(i_debug_instruction_list, i_rare_release_instruction_list):
    rare_command_in_release_exist_in_debug = 0

    for release_command in i_rare_release_instruction_list:
        if release_command in i_debug_instruction_list:
            rare_command_in_release_exist_in_debug += 1

    if len(i_rare_release_instruction_list) == 0 and rare_command_in_release_exist_in_debug == 0:
        return 1
    if len(i_rare_release_instruction_list) == 0:
        return 0
    return rare_command_in_release_exist_in_debug / float(len(i_rare_release_instruction_list))


# =========== Constant match =========== TODO: to take the 0.5 grade, and dropping jump instructions


def get_constant_list(i_start_func):
    constant_list = []
    func_instructions = FuncItems(i_start_func)

    for instruction in func_instructions:
        operand_type_0 = GetOpType(instruction, 0)
        operand_type_1 = GetOpType(instruction, 1)
        operand_type_2 = GetOpType(instruction, 2)

        if operand_type_0 == o_imm or operand_type_0 == o_mem:
            op = GetOpnd(instruction, 0)
            if op not in constant_list:
                constant_list += [op]

        if operand_type_1 == o_imm or operand_type_1 == o_mem:
            op = GetOpnd(instruction, 1)
            if op not in constant_list:
                constant_list += [op]

        if operand_type_2 == o_imm or operand_type_2 == o_mem:
            op = GetOpnd(instruction, 2)
            if op not in constant_list:
                constant_list += [op]

    return constant_list


def constant_match_feature(i_start_debug_func, i_start_release_func):
    release_constant_list = get_constant_list(i_start_debug_func)
    debug_constant_list = get_constant_list(i_start_release_func)

    amount_of_release_function_in_debug = 0

    for constant in release_constant_list:
        if constant in debug_constant_list:
            amount_of_release_function_in_debug += 1

    return amount_of_release_function_in_debug / float(len(release_constant_list))


def constant_match_feature_helper(i_debug_constant_list, i_release_constant_list):
    amount_of_release_function_in_debug = 0

    for constant in i_release_constant_list:
        if constant in i_debug_constant_list:
            amount_of_release_function_in_debug += 1

    if len(i_release_constant_list) == 0 and amount_of_release_function_in_debug == 0:
        return 1
    if len(i_release_constant_list) == 0:
        return 0
    return amount_of_release_function_in_debug / float(len(i_release_constant_list))


# =========== Jump match ===========


def get_jump_list(i_start_func):
    jump_list = []

    func_instructions = FuncItems(i_start_func)

    for instruction in func_instructions:
        mnemonic = GetMnem(instruction)
        if mnemonic in ['jmp', 'ja', 'jae', 'jb', 'jbe', 'je', 'jg', 'jge', 'jlr', 'jna', \
                        'jnae', 'jnb', 'jnbe', 'jc', 'jcxz', 'jecxz', 'jnc', 'jne', 'jng', \
                        'jnge', 'jnl', 'jnle', 'jno', 'jnp', 'jns', 'jnz', 'jo', 'jp', 'jpe', \
                        'jpo', 'js', 'jz', 'ja', 'jae', 'jb', 'jbe', 'jc', 'je', 'jz', 'jg', \
                        'jle', 'jl']:
            jump_list += [mnemonic]

    return jump_list


def jump_match_feature(i_start_debug_func, i_start_release_func):
    release_jump_list = get_jump_list(i_start_debug_func)
    debug_jump_list = get_jump_list(i_start_release_func)

    return len(release_jump_list) / float(len(debug_jump_list))


def jump_match_feature_helper(i_debug_jump_list, i_release_jump_list):
    if len(i_debug_jump_list) == 0 and len(i_release_jump_list) == 0:
        return 1
    if len(i_debug_jump_list) == 0:
        return 0

    result = len(i_release_jump_list) / float(len(i_debug_jump_list))

    if result > 1.0:
        return 1
    else:
        return result


# =========== Nested function match ===========


def get_func_name_list(i_start_func):
    nested_func_list = []

    func_instructions = FuncItems(i_start_func)

    for instruction in func_instructions:
        mnemonic = GetMnem(instruction)
        if mnemonic in ['call']:
            function = GetOpnd(instruction, 0)
            nested_func_list += [function]
    return nested_func_list


def nested_function_match_feature(i_start_debug_func, i_start_release_func):
    release_func_name_list = get_func_name_list(i_start_debug_func)
    debug_func_name_list = get_func_name_list(i_start_release_func)

    amount_of_release_and_debug = 0

    for function_name in release_func_name_list:
        if function_name in debug_func_name_list:
            amount_of_release_and_debug += 1

    return amount_of_release_and_debug / float(len(debug_func_name_list))


def nested_function_match_feature_helper(i_debug_func_name_list, i_release_func_name_list):
    amount_of_release_and_debug = 0
    checked_functions = []

    for debug_func_name in i_debug_func_name_list:
        for release_func_name in i_release_func_name_list:
            pos = debug_func_name.find(release_func_name)
            if -1 != pos and release_func_name not in checked_functions:
                checked_functions += [release_func_name]
                amount_of_release_and_debug += 1

    if len(i_release_func_name_list) == 0 and amount_of_release_and_debug == 0:
        return 1
    if len(i_release_func_name_list) == 0:
        return 0

    result = amount_of_release_and_debug / float(len(i_release_func_name_list))

    if result > 1.0:
        return 1
    else:
        return result


# =========== Number of args match ===========


def get_number_of_args(i_start_address):
    tif = tinfo_t()
    if not get_tinfo2(i_start_address, tif):
        guess_tinfo2(i_start_address, tif)
    function_data = func_type_data_t()
    tif.get_func_details(function_data)
    return function_data.size()


def number_of_args_match_feature(i_start_debug_func, i_start_release_func):
    release_func_number_of_args = get_number_of_args(i_start_debug_func)
    debug_func_number_of_args = get_number_of_args(i_start_release_func)

    if release_func_number_of_args == debug_func_number_of_args:
        return 1.0
    return 0.0


def number_of_args_match_helper(i_debug_func_number_of_args, i_release_func_number_of_args):
    if i_release_func_number_of_args == i_debug_func_number_of_args:
        return 1.0
    return 0.0


# =========== amount of menemonic match ===========

def get_amount_of_mnemonic(i_start_address):
    func_instructions = FuncItems(i_start_address)
    return len(list(func_instructions))


def amount_of_menemonic_match_feature(i_start_debug_func, i_start_release_func):
    release_func_amount_of_mnemonic = get_amount_of_mnemonic(i_start_debug_func)
    debug_func_amount_of_mnemonic = get_amount_of_mnemonic(i_start_release_func)

    if release_func_amount_of_mnemonic == debug_func_amount_of_mnemonic:
        return 1.0
    return 0.0


def amount_of_mnemonic_match_helper(debug_func_amount_of_mnemonic, release_func_amount_of_mnemonic):
    if debug_func_amount_of_mnemonic == 0:
        return 0.0

    if release_func_amount_of_mnemonic >= debug_func_amount_of_mnemonic:
        return 1.0

    return release_func_amount_of_mnemonic / float(debug_func_amount_of_mnemonic)


# =========== longest Common menomonic subsequence of menemonic match ===========

def lcs(X, Y):
    # find the length of the strings
    m = len(X)
    n = len(Y)

    # declaring the array for storing the dp values
    L = [[None] * (n + 1) for i in xrange(m + 1)]

    """Following steps build L[m+1][n+1] in bottom up fashion 
    Note: L[i][j] contains length of LCS of X[0..i-1] 
    and Y[0..j-1]"""
    for i in range(m + 1):
        for j in range(n + 1):
            if i == 0 or j == 0:
                L[i][j] = 0
            elif X[i - 1] == Y[j - 1]:
                L[i][j] = L[i - 1][j - 1] + 1
            else:
                L[i][j] = max(L[i - 1][j], L[i][j - 1])

                # L[m][n] contains the length of LCS of X[0..n-1] & Y[0..m-1]
    return L[m][n]


def get_sequence(i_start_func):
    sequence = ""

    func_instructions = FuncItems(i_start_func)

    for instruction in func_instructions:
        mnemonic = GetMnem(instruction)
        sequence += mnemonic

    return sequence


def mnemonic_subsequence_match_feature(i_start_debug_func, i_start_release_func):
    release_func_sequence = get_sequence(i_start_debug_func)
    debug_func_sequence = get_sequence(i_start_release_func)

    if len(debug_func_sequence) == 0 or len(release_func_sequence):
        return 0
    lcs_sequence = lcs(debug_func_sequence, release_func_sequence)

    return lcs_sequence / float(len(release_func_sequence))


def mnemonic_subsequence_match_helper(i_debug_func_sequence, i_release_func_sequence):
    if len(i_debug_func_sequence) == 0 or len(i_release_func_sequence) == 0:
        return 0
    lcs_sequence = lcs(i_debug_func_sequence, i_release_func_sequence)

    return lcs_sequence / float(len(i_release_func_sequence))


# =============================================
# ================  statistics ================
# =============================================


def get_export_func_name(address):
    for func in list(Entries()):
        if address == func[1]:
            return func[3]
    return None


def get_function_size(address):
    return len(list(idautils.FuncItems(address)))


def get_all_library_grades(functions):
    function_map = {}
    for f in functions:
        func_name = get_export_func_name(f)
        if func_name == None:
            func_name = get_func_name(f)

        features_map = {}

        features_map['Nested function'] = get_func_name_list(f)
        features_map['Jump match'] = get_jump_list(f)
        features_map['Constant match'] = get_constant_list(f)
        features_map['Command rare match'] = get_rare_instruction_list(f)
        features_map['Mnemonic match'] = get_func_mnemonic_list(f)
        features_map['Mnemonic subsequence match'] = get_sequence(f)
        features_map['Amount of menemonic match'] = get_amount_of_mnemonic(f)
        features_map['Number of args match'] = get_number_of_args(f)

        function_map[func_name] = features_map
    return function_map


def get_export_functions_map():
    export_functions = []
    for func in list(Entries()):
        if function_min_size < get_function_size(func[2]):
            export_functions += [[func[2], func[3]]]
    return export_functions


def get_export_functions():
    export_functions = []
    for func in list(Entries()):
        if function_min_size < get_function_size(func[2]):
            export_functions += [func[2]]
    return export_functions


def get_func_ea_list(i_start_func):
    nested_func_list = []
    func_instructions = FuncItems(i_start_func)

    for instruction in func_instructions:
        mnemonic = GetMnem(instruction)
        if mnemonic in ['call']:
            function_ea = GetOperandValue(instruction, 0)
            if function_ea != 0:
                nested_func_list += [function_ea]
    return nested_func_list


def build_func_graph(start_func, visited_functions):
    func_graph = {}
    visited_functions += [start_func]
    nested_func_name_list = get_func_ea_list(start_func)
    for func in nested_func_name_list:
        if func not in visited_functions:
            func_name = get_export_func_name(func)
            if func_name == None:
                func_name = get_func_name(func)
            func_graph[func_name] = build_func_graph(func, visited_functions)
    return func_graph


def build_graph(export_functions):
    all_export_func_graph = {}
    for f in export_functions:
        func_address = f[0]
        func_name = f[1]
        func_graph = build_func_graph(func_address, [])
        all_export_func_graph[func_name] = func_graph
    return all_export_func_graph


def thread_job(func_name_debug, index):
    final_grades = {}
    final_debug_grades = {}

    debug_function_grades = debug_library_grades[func_name_debug]

    debug_function_nested_function_grade = debug_function_grades['Nested function']
    debug_function_jump_match_grade = debug_function_grades['Jump match']
    debug_function_constant_match_grade = debug_function_grades['Constant match']
    debug_function_command_rare_match_grade = debug_function_grades['Command rare match']
    debug_function_mnemonic_match_grade = debug_function_grades['Mnemonic match']
    debug_function_mnemonic_subsequence_match_grade = debug_function_grades['Mnemonic subsequence match']
    debug_function_amount_of_menemonic_match_grade = debug_function_grades['Amount of menemonic match']
    debug_function_number_of_args_match_grade = debug_function_grades['Number of args match']

    for func_name_release in functions_name_array:
        features_map = {}

        release_grades = release_library_grades[func_name_release]

        release_function_nested_function_grade = release_grades['Nested function']
        release_function_jump_match_grade = release_grades['Jump match']
        release_function_constant_match_grade = release_grades['Constant match']
        release_function_command_rare_match_grade = release_grades['Command rare match']
        release_function_mnemonic_match_grade = release_grades['Mnemonic match']
        release_function_mnemonic_subsequence_match_grade = release_grades['Mnemonic subsequence match']
        release_function_amount_of_menemonic_match_grade = release_grades['Amount of menemonic match']
        release_function_number_of_args_match_grade = release_grades['Number of args match']

        features_map['Nested function'] = nested_function_match_feature_helper(debug_function_nested_function_grade,
                                                                               release_function_nested_function_grade)
        features_map['Jump match'] = jump_match_feature_helper(debug_function_jump_match_grade,
                                                               release_function_jump_match_grade)
        features_map['Constant match'] = constant_match_feature_helper(debug_function_constant_match_grade,
                                                                       release_function_constant_match_grade)
        features_map['Command rare match'] = rare_commands_feature_helper(debug_function_command_rare_match_grade,
                                                                          release_function_command_rare_match_grade)
        features_map['Mnemonic match'] = mnemonic_match_feaure_helper(debug_function_mnemonic_match_grade,
                                                                      release_function_mnemonic_match_grade)
        features_map['Mnemonic subsequence match'] = mnemonic_subsequence_match_helper(
            debug_function_mnemonic_subsequence_match_grade, release_function_mnemonic_subsequence_match_grade)
        features_map['Amount of menemonic match'] = amount_of_mnemonic_match_helper(
            debug_function_amount_of_menemonic_match_grade, release_function_amount_of_menemonic_match_grade)
        features_map['Number of args match'] = number_of_args_match_helper(debug_function_number_of_args_match_grade,
                                                                           release_function_number_of_args_match_grade)

        final_debug_grades[func_name_release] = features_map

    final_grades[func_name_debug] = final_debug_grades
    print "flashing to file: ", index, " thread name: ", threading.current_thread().name

    json_append(base + 'final_grades_n_by_n_' + str(file_index) + '.txt', final_grades)


def get_enum_by_name(i_enum_map, i_name):
    return i_enum_map[i_name]


def get_name_by_enum(i_enum_map, i_enum):
    keys = i_enum_map.keys()
    for key in keys:
        if i_enum_map[key] == i_enum:
            return key
    return 0


def set_enum(i_enum_map, i_name):
    i_enum_map[i_name] = get_enum()


def get_enum():
    global max_enum
    max_enum = max_enum + 1
    return max_enum - 1


def get_feature_enum():
    global max_feature_enum
    max_feature_enum = max_feature_enum + 1
    return max_feature_enum - 1


def set_feature_enum(i_enum_features_map, i_name):
    i_enum_features_map[i_name] = get_feature_enum()


def get_enum_by_feature(i_enum_features_map, i_name):
    return i_enum_features_map[i_name]


# ==================================================================
# ============================== main ==============================
# ==================================================================


# 1. Build grades for debug library

export_functions = get_export_functions()
debug_library_grades = get_all_library_grades(export_functions)

json_write(base + 'uclibc_debug_function_map.txt', debug_library_grades)

# 2. Build grades for debug graph

export_functions = get_export_functions_map()
debug_library_export_graph = build_graph(export_functions)

json_write(base + 'uclibc_debug_export_function_map.txt', debug_library_export_graph)

# 3. Build release function graph

export_functions = get_export_functions()
release_library_grades = get_all_library_grades(export_functions)

json_write(base + 'uclibc_release_function_map.txt', release_library_grades)

# 4. grades for release function library

export_functions = get_export_functions_map()
release_library_export_graph = build_graph(export_functions)

json_write(base + 'uclibc_release_export_function_map.txt', release_library_export_graph)

# 5. Merge grades (From this phase can running without IDA )

debug_library_grades = json_read(base + 'uclibc_debug_function_map.txt')
release_library_grades = json_read(base + 'uclibc_release_function_map.txt')
debug_library_export_graph = json_read(base + 'uclibc_debug_export_function_map.txt')
release_library_export_graph = json_read(base + 'uclibc_release_export_function_map.txt')

    # release_library_grades ['<function name>'] = '<grades>'
    # debug_library_grades ['<function name>'] = '<grades>'

    # debug_library_export_graph ['<function name>'] = '<sub functions>'
    # release_library_export_graph ['<function name>'] = '<sub functions>'

functions_name_array = []

for func_name in debug_library_export_graph:
    try:
        if func_name != "None":
            release_func_tree = release_library_export_graph[func_name]

            debug_func_tree = debug_library_export_graph[func_name]

            if release_func_tree != None and debug_func_tree != None:
                release_func_grades = release_library_grades[func_name]
                debug_func_grades = debug_library_grades[func_name]

                if release_func_grades != None and debug_func_grades != None:
                    functions_name_array += [func_name]  # functions_name_array[index] = func_name
    except KeyError as e:
        pass

for func_name_debug in functions_name_array:
    while True:
        if len(threading.enumerate()) < 14:
            t = threading.Thread(target=thread_job, args=(func_name_debug, index))
            t.start()
            index += 1
            if index % 500 == 0:
                file_index += 1
            break
        else:
            time.sleep(10)



# 6. export grades to Matlab

statistic = json_read(base + 'n_by_n\\final_grades_n_by_n.txt')
statistic_len = len(statistic)
features_len = len(features)

matrix_scores = [[[0 for k in xrange(features_len)]
                  for j in xrange(statistic_len)] for i in xrange(statistic_len)]  ##

for feature in features:
    set_feature_enum(enum_features_map, feature)

for item in statistic:
    set_enum(enum_map, item)

for item in statistic:
    row = get_enum_by_name(enum_map, item)
    sub_statistic = statistic[item]

    for sub_item in sub_statistic:
        col = get_enum_by_name(enum_map, sub_item)
        stat = sub_statistic[sub_item]

        for feature in features:
            matrix_scores[row][col][get_enum_by_feature(enum_features_map, feature)] = stat[feature]

json_write(base + 'enum_map.json', enum_map)
json_write(base + 'enum_features_map.json', enum_features_map)
scipy.io.savemat(base + 'statistic.mat', mdict={"statistic": matrix_scores})
