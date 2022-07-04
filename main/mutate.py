# -- coding:utf8 --


import string
import json
import random
from mitmproxy import ctx

def to_dict(input_str):
    try:
        obj = json.loads(input_str)
        return obj
    except:
        return None


def is_int(input_str):
    try:
        res = int(input_str)
        return True
    except:
        return False


def is_float(input_str):
    try:
        res = float(input_str)
        return True
    except:
        return False


def is_bool(input_str):
    try:
        res = float(input_str)
        return True
    except:
        return False


def to_data(input_str):
    # If the input_str can be transformed to another type, then transform it.
    # For example, input_str = '1234', then it will be transfromed to 1234
    # do not consider bool
    try:
        return eval(input_str)
    except:
        return input_str


def mutate_json(json_obj, mutate_limit):
    # mutate_limit is the number of mutated values reserved
    res = []
    for key, value in json_obj.items():
        if isinstance(value, dict):
            sub_res_list = mutate_json(value, mutate_limit)
            for sub_res in sub_res_list:
                json_obj[key] = sub_res
                res.append(json.loads(json.dumps(json_obj)))
        else:
            # ctx.log.warn(value)
            # ctx.log.warn(type(value))
            mutated_values = mutate_basic_data(value)
            if len(mutated_values) > mutate_limit:
                random.shuffle(mutated_values)
                mutated_values = mutated_values[:mutate_limit]
            for mutated_value in mutated_values:
                # ctx.log.warn(mutated_value)
                # ctx.log.warn(type(mutated_value))
                # if isinstance(value, float):
                #     mutated_value_float = float(mutated_value)
                json_obj[key] = mutated_value
                res.append(json.loads(json.dumps(json_obj)))
        json_obj[key] = value

    return res


def mutate_basic_data(original_value):
    if isinstance(original_value, bool):
        return [not original_value]
    else:
        original_value_str = str(original_value)
        if original_value_str.lower() in ["true", "false"]:
            bool_map = {
                "TRUE": "FALSE", "FALSE": "TRUE",
                "True": "False", "False": "True",
                "true": "false", "false": "true"
            }
            if original_value_str in bool_map:
                return [bool_map[original_value_str]]
    res = []
    c_list = list(original_value_str)
    for index, c in enumerate(c_list):
        new_c = mutate_up(c)
        if c != new_c:
            c_list[index] = new_c
            mutated_str = ''.join(c_list)
            mutated_value = mutated_str
            # if not isinstance(original_value, str):
                # mutated_value = eval(mutated_value)
            if mutated_value not in res:
                res.append(mutated_value)
        new_c = mutate_down(c)
        if c != new_c:
            c_list[index] = new_c
            mutated_str = ''.join(c_list)
            mutated_value = mutated_str
            # if not isinstance(original_value, str):
                # mutated_value = eval(mutated_value)
            if mutated_value not in res:
                if isinstance(original_value, float):
                    mutated_value_float = float(mutated_value)
                    res.append(mutated_value_float)
                else:
                    res.append(mutated_value)
        c_list[index] = c
    if not isinstance(original_value, str):
        for item in res:
            if isinstance(original_value, int):
                if original_value > 0 and item[0] == "0" and len(item) >= 2:
                    res.remove(item)
                elif original_value < 0 and item[1] == "0" and len(item) >= 3:
                    res.remove(item)
            elif isinstance(original_value, float):
                int_part_str = str(int(original_value))
                if original_value > 0 and int_part_str[0] == "0" and len(int_part_str) >= 2:
                    res.remove(item)
                elif original_value < 0 and int_part_str[1] == "0" and len(int_part_str) >= 3:
                    res.remove(item)
    return res
 

def check_repeat(mutate_list):
    res = []
    for item in mutate_list:
        try:
            tranformed_item = float(item)
            res.append(tranformed_item)
        except:
            res.append(item)
    assert len(res) == len(set(res)), "repeat"


def mutate_down(c):
    if c in string.digits or c in string.ascii_letters:
        if c == '0' or c == 'A' or c == 'a':
            return c
        return chr(ord(c) - 1)
    return c


def mutate_up(c):
    if c in string.digits or c in string.ascii_letters:
        if c == '9' or c == 'Z' or c == 'z':
            return c
        return chr(ord(c) + 1)
    return c


if __name__ == "__main__":
    # print(mutate_basic_data("77.21935953944921"))
    print(mutate_basic_data("5"))
