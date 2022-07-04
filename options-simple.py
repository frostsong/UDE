"""
Add a new mitmproxy option.

Usage:

    mitmproxy -s options-simple.py --set addheader true
    mitmproxy --mode upstream:http://127.0.0.1:7890 -s options-simple.py
"""
from re import X
from kaitaistruct import KaitaiStream
from mitmproxy.contrib.kaitaistruct import google_protobuf
import myutil
import os
import random
import json
import judge_traffic_privacy
from mitmproxy import http
from mitmproxy import ctx
from mitmproxy.contentviews import protobuf,base,msgpack
import mutate
import pb_part
import io
import xmltodict
import typing
import msgpack


original_flow_recorder = {}  # 记录信息原始flow的信息

monotonic_param_recorder = {}  # 只记录流量中单调变化的参数，值保存在original_flow_recorder中

other_data_seed = {} # 记录其他流量中发现的隐私项相关数据，以供后面mutate使用

unrelated_key_list = ["android","limit", "offset", "page", "skip", "row", "size", "start", "begin", "from", "end", "to", "device","front","dev"]

unrelated_url_keyword_list = ["preference", "search", "public", "register"]

unrelated_key_sentences_list = ["android_id","devices_id","pag_num"]

def get_req_body(flow: http.HTTPFlow):
    try:
        res = flow.request.get_text()
        return res
    except:
        return None


def get_resp_body(flow: http.HTTPFlow):
    try:
        res = flow.response.get_text()
        return res
    except:
        return None


def check_mutated_replay_res_get(mutated_flow: http.HTTPFlow):
    # Compare get request res with the original
    # If different, save it to file
    url_without_query = mutated_flow.request.host + mutated_flow.request.path.split("?")[0]
    record_dir = url_without_query.replace("/", "]")
    record_dir = os.path.join("test", record_dir)
    if url_without_query in original_flow_recorder:
        original_resp_data = original_flow_recorder[url_without_query]["resp_data"]
        mutated_resp_data_str = mutated_flow.response.get_text()
        mutated_resp_data = json.loads(mutated_resp_data_str)  # 将结果转为dict对象

        mutated_query = dict(mutated_flow.request.query)
        for key, value in mutated_query.items():
            mutated_query[key] = mutate.to_data(value)
        original_query = original_flow_recorder[url_without_query]["query"]

        query_diff = myutil.compare_query(original_query, mutated_query)

        is_different, resp_diff = myutil.find_difference_of_privacy(original_resp_data, mutated_resp_data)
        if is_different:
            """将新产生的结果保存到文件"""
            myutil.write_content_to_file(record_dir, query_diff + ".json", mutated_resp_data_str)
            record_str = "[GET] " + url_without_query + "\n"  # to add some record:
            record_str += (query_diff + " " + resp_diff + "\n\n")
            myutil.append_content_to_file("test/record.txt", record_str)
            ctx.log.warn("Mutated flow: find difference in privacy, recorded")
        else:
            ctx.log.warn("Mutated flow: all the same\n")
    else:
        ctx.log.error("Bug, not find original res: " + url_without_query)
    pass


def check_mutated_replay_res_post(mutated_flow: http.HTTPFlow):
    # Compare post request res with the original
    # If different, save it to file
    post_url = mutated_flow.request.host + mutated_flow.request.path
    record_dir = post_url.replace("/", "]")
    record_dir = os.path.join("test", record_dir)
    if post_url in original_flow_recorder:
        original_resp_data = original_flow_recorder[post_url]["resp_data"]
        mutated_resp_data_str = mutated_flow.response.get_text()
        mutated_resp_data = json.loads(mutated_resp_data_str)

        post_diff = None
        if "urlencoded_form" in original_flow_recorder[post_url]:
            mutated_urlencoded_form = dict(mutated_flow.request.urlencoded_form)
            original_urlencoded_form = original_flow_recorder[post_url]["urlencoded_form"]
            post_diff = myutil.compare_form(original_urlencoded_form, mutated_urlencoded_form)
        else:
            mutated_json = json.loads(mutated_flow.request.get_text())
            original_json = original_flow_recorder[post_url]["req_json"]
            post_diff = myutil.compare_json(original_json, mutated_json)

        is_different, resp_diff = myutil.find_difference_of_privacy(original_resp_data, mutated_resp_data)
        if is_different:
            """将新产生的结果保存到文件"""
            myutil.write_content_to_file(record_dir, post_diff + ".json", mutated_resp_data_str)
            record_str = "[POST] " + post_url + "\n"  # to add some record
            record_str += (post_diff + " " + resp_diff + "\n\n")
            myutil.append_content_to_file("test/record.txt", record_str)
            ctx.log.warn("Mutated flow: find difference, recorded")
        else:
            ctx.log.warn("Mutated flow: all the same\n")

    else:
        ctx.log.error("Bug, not find original res: " + post_url)
    pass


def check_mutated_replay_res(mutated_flow: http.HTTPFlow):
    if mutated_flow.request.method == "GET":
        check_mutated_replay_res_get(mutated_flow)
    elif mutated_flow.request.method == "POST":
        check_mutated_replay_res_post(mutated_flow)


def is_mutated_flow(replayed_flow: http.HTTPFlow):
    """
    Check if the flow request params are the same as the original flow.
    If the same, the replayed_flow is not mutated.
    """
    if replayed_flow.request.method == "GET":
        url_without_query = replayed_flow.request.host + replayed_flow.request.path.split("?")[0]
        replayed_query = dict(replayed_flow.request.query)
        for key, value in replayed_query.items():
            replayed_query[key] = mutate.to_data(value)  # transform a string value to its original form
        original_query = original_flow_recorder[url_without_query]["query"]
        return replayed_query != original_query
    elif replayed_flow.request.method == "POST":
        post_url = replayed_flow.request.host + replayed_flow.request.path
        if post_url not in original_flow_recorder:
            ctx.log.error(original_flow_recorder.keys())
        if "urlencoded_form" in original_flow_recorder[post_url]:
            replayed_urlencoded_form = dict(replayed_flow.request.urlencoded_form)
            original_urlencoded_form = original_flow_recorder[post_url]["urlencoded_form"]
            return replayed_urlencoded_form != original_urlencoded_form
        else:
            replayed_json = json.loads(replayed_flow.request.get_text())
            original_json = original_flow_recorder[post_url]["req_json"]
            return replayed_json != original_json


def check_random_res_in_replayed_flow(replayed_flow: http.HTTPFlow):
    """
    Check if the flow response text are the same as the original flow.
    If not the same, there is a random factor in this traffic result, drop it.
    """
    if replayed_flow.request.method == "GET":
        url_without_query = replayed_flow.request.host + replayed_flow.request.path.split("?")[0]
        original_resp_data = original_flow_recorder[url_without_query]["resp_data"]
        replayed_resp_data_str = replayed_flow.response.get_text()
        replayed_resp_data = json.loads(replayed_resp_data_str)  # 将结果转为dict对象
        is_different, difference = myutil.find_difference_of_privacy(original_resp_data, replayed_resp_data)
        # if is_different:
        #     myutil.write_content_to_file(os.path.join("test", "get " + url_without_query.replace("/", "]")),
        #                                  "original_traffic.json", json.dumps(original_resp_data))
        #     myutil.write_content_to_file(os.path.join("test", "get " + url_without_query.replace("/", "]")),
        #                                  "replayed_traffic.json", json.dumps(replayed_resp_data))
        return is_different
    elif replayed_flow.request.method == "POST":
        post_url = replayed_flow.request.host + replayed_flow.request.path
        original_resp_data = original_flow_recorder[post_url]["resp_data"]
        replayed_resp_data_str = replayed_flow.response.get_text()
        replayed_resp_data = json.loads(replayed_resp_data_str)
        is_different, difference = myutil.find_difference_of_privacy(original_resp_data, replayed_resp_data)
        # if is_different:
        #     myutil.write_content_to_file(os.path.join("test", "post " + post_url.replace("/", "]")),
        #                                  "original_traffic.json", json.dumps(original_resp_data))
        #     myutil.write_content_to_file(os.path.join("test", "post " + post_url.replace("/", "]")),
        #                                  "replayed_traffic.json", json.dumps(replayed_resp_data))
        return is_different


def replay_get_with_mutation(flow: http.HTTPFlow):
    # replay the get request
    url_without_query = flow.request.host + flow.request.path.split("?")[0]
    if url_without_query not in original_flow_recorder:
        ctx.log.error("Error, not find original flow!")
        return

    query_dict = original_flow_recorder[url_without_query]["query"]
    resp_data_str = flow.response.get_text()

    ctx.log.warn("Replay get " + url_without_query)
    record_dir = url_without_query.replace("/", "]")
    record_dir = os.path.join("test", record_dir)
    myutil.write_content_to_file(record_dir, "original_query.json", json.dumps(query_dict))
    myutil.write_content_to_file(record_dir, "original_traffic.json", resp_data_str)
    for key, value in query_dict.items():
        is_unrelated_key = False
        if key in unrelated_key_sentences_list:
            break
        key_word_list = myutil.to_word_sequence_lower(key)
        for key_word in key_word_list:
            if key_word in unrelated_key_list:
                is_unrelated_key = True
                break
        if is_unrelated_key:
            continue

        mutated_query_values = mutate.mutate_basic_data(value)
        if len(mutated_query_values) > 4:
            random.shuffle(mutated_query_values)
            mutated_query_values = mutated_query_values[:4]

        # if key in other_data_seed:  #seed集
        #     for seed_value in other_data_seed(key):
        #         mutated_query_values.append(seed_value)

        for mutated_query_value in mutated_query_values:
            new_flow = flow.copy()
            new_flow.request.query[key] = mutated_query_value

            # new_flow.request.headers["replay"] = "true"  # 标记一下流量方便查看
            new_flow.request.headers["mutate"] = "True"
            ctx.master.commands.call("replay.client", [new_flow])
    pass


def replay_post_with_mutation(flow: http.HTTPFlow):
    # replay the post request
    post_url = flow.request.host + flow.request.path
    if post_url not in original_flow_recorder:
        ctx.log.error("Error, not find original flow!")
        return

    if flow.request.urlencoded_form:
        """考虑url_encoded_form格式的内容"""
        mutate_post_in_form(flow, post_url)
        return
    elif "content-type" in dict(flow.request.headers) or "Content-Type" in dict(flow.request.headers):
        if flow.request.headers["content-type"].startswith("application/json"):
            """考虑json格式的内容"""
            mutate_post_in_json(flow, post_url)
            return
    ctx.log.warn("No mutatable item detected!")


def mutate_post_in_form(flow: http.HTTPFlow, post_url):
    form_dict = dict(flow.request.urlencoded_form)
    resp_data_str = flow.response.get_text()
    # original_flow_recorder[post_url] = {
    #     "urlencoded_form": form_dict,
    #     "resp_data": json.loads(resp_data_str)
    # }

    ctx.log.warn("Replaying post " + post_url)
    record_dir = post_url.replace("/", "]")
    record_dir = os.path.join("test", record_dir)
    myutil.write_content_to_file(record_dir, "original_form.json", json.dumps(form_dict))
    myutil.write_content_to_file(record_dir, "original_traffic.json", resp_data_str)
    for key, value in form_dict.items():
        is_unrelated_key = False
        key_word_list = myutil.to_word_sequence_lower(key)
        for key_word in key_word_list:
            if key_word in unrelated_key_list:
                is_unrelated_key = True
                break
        if is_unrelated_key:
            continue
        # """value可能是一个普通的str，也有可能是一个str格式的json对象"""
        mutated_form_values = None
        value2json = mutate.to_dict(value)
        if isinstance(value2json, dict):  # 说明这个字段是json格式的
            mutated_form_values = mutate.mutate_json(value2json, 1)
            mutated_form_values = [json.dumps(mutated_form_value) for mutated_form_value in mutated_form_values]
        else:
            mutated_form_values = mutate.mutate_basic_data(value)

        if len(mutated_form_values) > 4:
            random.shuffle(mutated_form_values)
            mutated_form_values = mutated_form_values[:4]

        for mutated_form_value in mutated_form_values:
            new_flow = flow.copy()
            new_flow.request.urlencoded_form[key] = mutated_form_value
            new_flow.request.headers["mutate"] = "True"
            ctx.master.commands.call("replay.client", [new_flow])
    pass


def mutate_post_in_json(flow: http.HTTPFlow, post_url):
    request_json_str = get_req_body(flow)
    if not request_json_str:
        return
    request_json = mutate.to_dict(request_json_str)
    if not isinstance(request_json, dict):
        return

    resp_data_str = flow.response.get_text()
    # original_flow_recorder[post_url] = {
    #     "req_json": request_json,
    #     "resp_data": json.loads(resp_data_str)
    # }

    ctx.log.warn("Replaying post " + post_url)
    record_dir = post_url.replace("/", "]")
    record_dir = post_url.replace("?", "-")
    record_dir = os.path.join("test", record_dir)
    myutil.write_content_to_file(record_dir, "original_json.json", request_json_str)
    myutil.write_content_to_file(record_dir, "original_traffic.json", resp_data_str)

    mutated_json_values = mutate.mutate_json(request_json, 1)

    for mutated_json_value in mutated_json_values:
        new_flow = flow.copy()
        new_flow.request.set_text(json.dumps(mutated_json_value))
        new_flow.request.headers["mutate"] = "True"
        ctx.master.commands.call("replay.client", [new_flow])
    pass


def replay_without_mutation(flow: http.HTTPFlow):
    """
    Replay the original flow, and check if the the result is random
    """
    if flow.request.method in ["GET", "POST"]:
        if flow.request.method == "GET":
            if not flow.request.query:
                """Nothing to mutate."""
                ctx.log.warn("[No mutatable query]")
                return
            url_without_query = flow.request.host + flow.request.path.split("?")[0]
            query_dict = dict(flow.request.query)
            for key, value in query_dict.items():
                query_dict[key] = mutate.to_data(value)  # transform a string value to its original form

            resp_data_str = flow.response.get_text()
            original_flow_recorder[url_without_query] = {
                "query": query_dict,
                "resp_data": json.loads(resp_data_str),
                "repeated_params": {}
            }
            ctx.log.warn("[Check Random][" + flow.request.method + "] " + flow.request.url)
            simple_replay(flow)
        else:
            """
            Only mutate when the request body is either urlencoded_form or json
            """
            post_url = flow.request.host + flow.request.path
            if flow.request.urlencoded_form:
                form_dict = dict(flow.request.urlencoded_form)
                resp_data_str = flow.response.get_text()
                original_flow_recorder[post_url] = {
                    "urlencoded_form": form_dict,
                    "resp_data": json.loads(resp_data_str)
                }
                ctx.log.warn("[Check Random][" + flow.request.method + "] " + flow.request.url)
                simple_replay(flow)
            elif "content-type" in dict(flow.request.headers) or "Content-Type" in dict(flow.request.headers):
                if flow.request.headers["content-type"].startswith("application/json"):
                    request_json_str = get_req_body(flow)
                    request_json = mutate.to_dict(request_json_str)
                    if not request_json:
                        """In case the request body contains nothing"""
                        return
                    resp_data_str = flow.response.get_text()
                    original_flow_recorder[post_url] = {
                        "req_json": request_json,
                        "resp_data": json.loads(resp_data_str)
                    }
                    ctx.log.warn("[Check Random][" + flow.request.method + "] " + flow.request.url)
                    simple_replay(flow)


def simple_replay(flow: http.HTTPFlow):
    flow = flow.copy()
    # flow.request.headers["replay"] = "True"
    ctx.master.commands.call("replay.client", [flow])
    ctx.log.warn("[Replay success][" + flow.request.method + "] " + flow.request.url)
    pass


def replay_with_mutation(flow: http.HTTPFlow):
    """
    1.保存原始结果
    2.生成变异值
    3.对每个变异值产生一条新流量
    """
    if flow.request.method == "GET":
        replay_get_with_mutation(flow)
    elif flow.request.method == "POST":
        replay_post_with_mutation(flow)


def is_unrelated_request(request_path):
    words = myutil.to_word_sequence_lower(request_path)
    for word in words:
        if word in unrelated_url_keyword_list:
            return True
    return False

def xml_to_json(xml_str):
    # parse是的xml解析器
    xml_parse = xmltodict.parse(xml_str)
    # json库dumps()是将dict转化成json格式,loads()是将json转化成dict格式。
    # dumps()方法的ident=1,格式化json
    json_str = json.dumps(xml_parse, indent=1)
    return json_str

def json_to_xml(json_str):
    xml_str = xmltodict.unparse(json_str, pretty=1)
    return xml_str

def form_msgpack(data):
    try:
        return msgpack.format_msgpack(msgpack.unpackb(data, raw=False))
    except (ValueError, msgpack.ExtraData, msgpack.FormatError, msgpack.StackError):
        return object()

#protobuf part

def get_req_pb_form(request_body):
    res = request_body.split(":",1)
    res_json = json.loads(res[1])
    return res_json

def get_resp_body_content(flow: http.HTTPFlow):
    try:
        res = flow.response.get_content()
        return res
    except:
        return None

def get_req_body_content(flow: http.HTTPFlow):
    try:
        res = flow.request.get_content()
        return res
    except:
        return None

def get_resp_body_pb(flow: http.HTTPFlow):
    try:
        res = protobuf.format_pbuf(flow.response.get_content())
        return res
    except:
        return None

def get_req_body_pb(flow: http.HTTPFlow):
    try:
        res = protobuf.format_pbuf(flow.request.get_content())
        return res
    except:
        return None

def replay_without_mutation_pb(flow:http.HTTPFlow):
    if flow.request.method == "POST":
        post_url = flow.request.host + flow.request.path
        if "content-type" in dict(flow.request.headers) or "Content-Type" in dict(flow.request.headers):
            if flow.request.headers["content-type"].startswith("application/x-protobuf"):
                request_pb = get_req_body_pb(flow)
                if not request_pb:
                    """In case the request body contains nothing"""
                    return
                resp_data_pb = get_resp_body_pb(flow)
                original_flow_recorder[post_url] = {
                    "req_pb": request_pb,
                    "resp_data": resp_data_pb
                }
                ctx.log.warn("[Check Random][" + flow.request.method + "] " + flow.request.url)
                # request_content_str = flow.request.get_text_pb()
                # if not request_content_str:
                #     return
                # request_pb_str = request_content_str.split('\"',1)
                # request_json = mutate.to_dict(request_pb_str[1])
                # mutated_json_values = mutate.mutate_json(request_json, 1)
                # for mutated_value in mutated_json_values:
                #     b = json.dumps(mutated_value)
                #     d = b.replace(" ", "")
                #     c = request_pb_str[0]+"\""+ d
                #     ctx.log.warn(request_content_str)
                #     ctx.log.warn(c)
                simple_replay(flow)

def check_random_res_in_replayed_flow_pb(replayed_flow: http.HTTPFlow):
    if replayed_flow.request.method == "POST":
        post_url = replayed_flow.request.host + replayed_flow.request.path
        original_resp_data = original_flow_recorder[post_url]["resp_data"]
        replayed_resp_data_pb = get_resp_body_pb(replayed_flow)
        if original_resp_data == replayed_resp_data_pb:
            return False
        else:
            return True

def is_mutated_flow_pb(replayed_flow: http.HTTPFlow):
    if replayed_flow.request.method == "POST":
        post_url = replayed_flow.request.host + replayed_flow.request.path
        if post_url not in original_flow_recorder:
            ctx.log.error(original_flow_recorder.keys())
        if "req_pb" in original_flow_recorder[post_url]:
            replayed_url_pb = get_req_body_pb(replayed_flow)
            original_url_pb = original_flow_recorder[post_url]["req_pb"]
            return replayed_url_pb != original_url_pb

def replay_with_mutation_pb(flow: http.HTTPFlow):
    post_url = flow.request.host + flow.request.path
    if post_url not in original_flow_recorder:
        ctx.log.error("Error, not find original flow!")
        return

    if "content-type" in dict(flow.request.headers) or "Content-Type" in dict(flow.request.headers):
        if flow.request.headers["content-type"].startswith("application/x-protobuf"):
            mutate_post_in_pb(flow, post_url)
            return
    ctx.log.warn("No mutatable item detected!")

def mutate_post_in_pb(flow: http.HTTPFlow, post_url):
    request_content_str = flow.request.get_text_pb()
    if not request_content_str:
        return
    request_pb_str = request_content_str.split('\"',1)
    request_json = mutate.to_dict(request_pb_str[1])
    if not isinstance(request_json, dict):
        return

    resp_data_pb = get_resp_body_pb(flow)
    ctx.log.warn("Replaying post " + post_url)
    record_dir = post_url.replace("/", "]")
    record_dir = post_url.replace("?", "-")
    record_dir = os.path.join("test", record_dir)
    myutil.write_content_to_file(record_dir, "original_json.txt", request_content_str)
    myutil.write_content_to_file(record_dir, "original_traffic.txt", resp_data_pb)

    mutated_json_values = mutate.mutate_json(request_json, 1)

    for mutated_json_value in mutated_json_values:
        new_flow = flow.copy()
        mutated_all = json.dumps(mutated_json_value)
        new_flow.request.set_text(request_pb_str[0] + "\"" + mutated_all.replace(" ", ""))
        new_flow.request.headers["mutate"] = "True"
        ctx.master.commands.call("replay.client", [new_flow])
    pass

def check_mutated_replay_res_pb(mutated_flow: http.HTTPFlow):
    # Compare post request res with the original
    # If different, save it to file
    post_url = mutated_flow.request.host + mutated_flow.request.path
    record_dir = post_url.replace("/", "]")
    record_dir = os.path.join("test", record_dir)
    if post_url in original_flow_recorder:
        original_resp_data_pb = original_flow_recorder[post_url]["resp_data"]
        mutated_resp_data_pb = get_resp_body_pb(mutated_flow)

        post_diff = None
        if "req_pb" in original_flow_recorder[post_url]:
            mutated_req_pb_middle = get_req_body_pb(mutated_flow)
            original_req_pb_middle = original_flow_recorder[post_url]["req_pb"]
            mutated_req_pb = get_req_pb_form(mutated_req_pb_middle)
            original_req_pb = get_req_pb_form(original_req_pb_middle)
            post_diff = myutil.compare_form(original_req_pb, mutated_req_pb)

        if original_resp_data_pb != mutated_resp_data_pb:
            """将新产生的结果保存到文件"""
            myutil.write_content_to_file(record_dir, post_diff + ".txt", mutated_resp_data_pb)
            record_str = "[POST] " + post_url + "\n"  # to add some record
            record_str += (post_diff + "\n\n")
            myutil.append_content_to_file("test/record.txt", record_str)
            ctx.log.warn("Mutated flow: find difference, recorded")
        else:
            ctx.log.warn("Mutated flow: all the same\n")

    else:
        ctx.log.error("Bug, not find original res: " + post_url)
    pass

#xml part
def replay_without_mutation_xml(flow: http.HTTPFlow):
    """
    Replay the original flow, and check if the the result is random
    """
    if flow.request.method in ["GET", "POST"]:
        if flow.request.method == "GET":
            if not flow.request.query:
                """Nothing to mutate."""
                ctx.log.warn("[No mutatable query]")
                return
            url_without_query = flow.request.host + flow.request.path.split("?")[0]
            query_dict = dict(flow.request.query)
            for key, value in query_dict.items():
                query_dict[key] = mutate.to_data(value)  # transform a string value to its original form

            resp_data_str = xml_to_json(flow.response.get_text())
            original_flow_recorder[url_without_query] = {
                "query": query_dict,
                "resp_data": json.loads(resp_data_str),
                "repeated_params": {}
            }
            ctx.log.warn("[Check Random][" + flow.request.method + "] " + flow.request.url)
            simple_replay(flow)
        else:
            post_url = flow.request.host + flow.request.path
            resp_data_str = xml_to_json(flow.response.get_text())
            request_data_str = xml_to_json(flow.request.get_text())
            original_flow_recorder[post_url] = {
                "request_data": json.loads(request_data_str),
                "resp_data": json.loads(resp_data_str)
            }
            ctx.log.warn("[Check Random][" + flow.request.method + "] " + flow.request.url)
            simple_replay(flow)

def is_mutated_flow_xml(replayed_flow: http.HTTPFlow):
    if replayed_flow.request.method == "GET":
        url_without_query = replayed_flow.request.host + replayed_flow.request.path.split("?")[0]
        replayed_query = dict(replayed_flow.request.query)
        for key, value in replayed_query.items():
            replayed_query[key] = mutate.to_data(value)  # transform a string value to its original form
        original_query = original_flow_recorder[url_without_query]["query"]
        return replayed_query != original_query
    elif replayed_flow.request.method == "POST":
        post_url = replayed_flow.request.host + replayed_flow.request.path
        if post_url not in original_flow_recorder:
            ctx.log.error(original_flow_recorder.keys())
        if "request_data" in original_flow_recorder[post_url]:
            replayed_json = json.loads(xml_to_json(replayed_flow.request.get_text()))
            original_json = original_flow_recorder[post_url]["request_data"]
            return replayed_json != original_json

def check_random_res_in_replayed_flow_xml(replayed_flow: http.HTTPFlow):
    if replayed_flow.request.method == "GET":
        url_without_query = replayed_flow.request.host + replayed_flow.request.path.split("?")[0]
        original_resp_data = original_flow_recorder[url_without_query]["resp_data"]
        replayed_resp_data_str = xml_to_json(replayed_flow.response.get_text())
        replayed_resp_data = json.loads(replayed_resp_data_str)  
        is_different, difference = myutil.find_difference_of_privacy(original_resp_data, replayed_resp_data)
        return is_different
    elif replayed_flow.request.method == "POST":
        post_url = replayed_flow.request.host + replayed_flow.request.path
        original_resp_data = original_flow_recorder[post_url]["resp_data"]
        replayed_resp_data_str = xml_to_json(replayed_flow.response.get_text())
        replayed_resp_data = json.loads(replayed_resp_data_str)
        is_different, difference = myutil.find_difference_of_privacy(original_resp_data, replayed_resp_data)
        return is_different

def replay_with_mutation_xml(flow: http.HTTPFlow):
    if flow.request.method == "GET":
        replay_get_with_mutation_xml(flow)
    elif flow.request.method == "POST":
        replay_post_with_mutation_xml(flow)

def replay_get_with_mutation_xml(flow: http.HTTPFlow):
    # replay the get request
    url_without_query = flow.request.host + flow.request.path.split("?")[0]
    if url_without_query not in original_flow_recorder:
        ctx.log.error("Error, not find original flow!")
        return

    query_dict = original_flow_recorder[url_without_query]["query"]
    resp_data_str = xml_to_json(flow.response.get_text())

    ctx.log.warn("Replay get " + url_without_query)
    record_dir = url_without_query.replace("/", "]")
    record_dir = os.path.join("test", record_dir)
    myutil.write_content_to_file(record_dir, "original_query.json", json.dumps(query_dict))
    myutil.write_content_to_file(record_dir, "original_traffic.json", resp_data_str)
    for key, value in query_dict.items():
        is_unrelated_key = False
        key_word_list = myutil.to_word_sequence_lower(key)
        for key_word in key_word_list:
            if key_word in unrelated_key_list:
                is_unrelated_key = True
                break
        if is_unrelated_key:
            continue
        mutated_query_values = mutate.mutate_basic_data(value)
        if len(mutated_query_values) > 4:
            random.shuffle(mutated_query_values)
            mutated_query_values = mutated_query_values[:4]

        for mutated_query_value in mutated_query_values:
            new_flow = flow.copy()
            new_flow.request.query[key] = mutated_query_value

            # new_flow.request.headers["replay"] = "true"  # 标记一下流量方便查看
            new_flow.request.headers["mutate"] = "True"
            ctx.master.commands.call("replay.client", [new_flow])
    pass

def replay_post_with_mutation_xml(flow: http.HTTPFlow):
    # replay the post request
    post_url = flow.request.host + flow.request.path
    if post_url not in original_flow_recorder:
        ctx.log.error("Error, not find original flow!")
        return

    if "content-type" in dict(flow.request.headers) or "Content-Type" in dict(flow.request.headers):
        if flow.request.headers["content-type"].startswith("application/xml"):
            request_json_str = xml_to_json(get_req_body(flow))
            if not request_json_str:
                return
            request_json = mutate.to_dict(request_json_str)
            if not isinstance(request_json, dict):
                return

            resp_data_str = xml_to_json(flow.response.get_text())

            ctx.log.warn("Replaying post " + post_url)
            record_dir = post_url.replace("/", "]")
            record_dir = post_url.replace("?", "-")
            record_dir = os.path.join("test", record_dir)
            myutil.write_content_to_file(record_dir, "original_json.json", request_json_str)
            myutil.write_content_to_file(record_dir, "original_traffic.json", resp_data_str)

            mutated_json_values = mutate.mutate_json(request_json, 1)

            for mutated_json_value in mutated_json_values:
                new_flow = flow.copy()
                new_flow.request.set_text(json_to_xml(json.dumps(mutated_json_value)))
                new_flow.request.headers["mutate"] = "True"
                ctx.master.commands.call("replay.client", [new_flow])
        else:
            ctx.log.warn("No mutatable item detected!")

def check_mutated_replay_res_xml(mutated_flow: http.HTTPFlow):
    if mutated_flow.request.method == "GET":
        check_mutated_replay_res_get_xml(mutated_flow)
    elif mutated_flow.request.method == "POST":
        check_mutated_replay_res_post_xml(mutated_flow)

def check_mutated_replay_res_get_xml(mutated_flow: http.HTTPFlow):
    url_without_query = mutated_flow.request.host + mutated_flow.request.path.split("?")[0]
    record_dir = url_without_query.replace("/", "]")
    record_dir = os.path.join("test", record_dir)
    if url_without_query in original_flow_recorder:
        original_resp_data = original_flow_recorder[url_without_query]["resp_data"]
        mutated_resp_data_str = xml_to_json(mutated_flow.response.get_text())
        mutated_resp_data = json.loads(mutated_resp_data_str)  # 将结果转为dict对象

        mutated_query = dict(mutated_flow.request.query)
        for key, value in mutated_query.items():
            mutated_query[key] = mutate.to_data(value)
        original_query = original_flow_recorder[url_without_query]["query"]

        query_diff = myutil.compare_query(original_query, mutated_query)

        is_different, resp_diff = myutil.find_difference_of_privacy(original_resp_data, mutated_resp_data)
        if is_different:
            """将新产生的结果保存到文件"""
            myutil.write_content_to_file(record_dir, query_diff + ".json", mutated_resp_data_str)
            record_str = "[GET] " + url_without_query + "\n"  # to add some record:
            record_str += (query_diff + " " + resp_diff + "\n\n")
            myutil.append_content_to_file("test/record.txt", record_str)
            ctx.log.warn("Mutated flow: find difference in privacy, recorded")
        else:
            ctx.log.warn("Mutated flow: all the same\n")
    else:
        ctx.log.error("Bug, not find original res: " + url_without_query)
    pass

def check_mutated_replay_res_post_xml(mutated_flow: http.HTTPFlow):
    post_url = mutated_flow.request.host + mutated_flow.request.path
    record_dir = post_url.replace("/", "]")
    record_dir = os.path.join("test", record_dir)
    if post_url in original_flow_recorder:
        original_resp_data = original_flow_recorder[post_url]["resp_data"]
        mutated_resp_data_str = xml_to_json(mutated_flow.response.get_text())
        mutated_resp_data = json.loads(mutated_resp_data_str)

        post_diff = None
        if "request_data" in original_flow_recorder[post_url]:
            mutated_json = json.loads(xml_to_json(mutated_flow.request.get_text()))
            original_json = original_flow_recorder[post_url]["request_data"]
            post_diff = myutil.compare_json(original_json, mutated_json)

        is_different, resp_diff = myutil.find_difference_of_privacy(original_resp_data, mutated_resp_data)
        if is_different:
            """将新产生的结果保存到文件"""
            myutil.write_content_to_file(record_dir, post_diff + ".json", mutated_resp_data_str)
            record_str = "[POST] " + post_url + "\n"  # to add some record
            record_str += (post_diff + " " + resp_diff + "\n\n")
            myutil.append_content_to_file("test/record.txt", record_str)
            ctx.log.warn("Mutated flow: find difference, recorded")
        else:
            ctx.log.warn("Mutated flow: all the same\n")

    else:
        ctx.log.error("Bug, not find original res: " + post_url)
    pass

#msgpack part
def replay_without_mutation_mp(flow: http.HTTPFlow):
        if flow.request.method == "GET":
            post_url = flow.request.host + flow.request.path
            resp_data_str = form_msgpack(flow.response.get_content())
            request_data_str = form_msgpack(flow.request.get_content())
            original_flow_recorder[post_url] = {
                "request_data": json.loads(request_data_str),
                "resp_data": json.loads(resp_data_str)
            }
            ctx.log.warn("[Check Random][" + flow.request.method + "] " + flow.request.url)
            simple_replay(flow)

def is_mutated_flow_mp(replayed_flow: http.HTTPFlow):
    if replayed_flow.request.method == "POST":
        post_url = replayed_flow.request.host + replayed_flow.request.path
        if post_url not in original_flow_recorder:
            ctx.log.error(original_flow_recorder.keys())
        if "request_data" in original_flow_recorder[post_url]:
            replayed_json = json.loads(form_msgpack(replayed_flow.request.get_content()))
            original_json = original_flow_recorder[post_url]["request_data"]
            return replayed_json != original_json

def check_random_res_in_replayed_flow_mp(replayed_flow: http.HTTPFlow):
    if replayed_flow.request.method == "POST":
        post_url = replayed_flow.request.host + replayed_flow.request.path
        original_resp_data = original_flow_recorder[post_url]["resp_data"]
        replayed_resp_data_str = form_msgpack(replayed_flow.response.get_content())
        replayed_resp_data = json.loads(replayed_resp_data_str)
        is_different, difference = myutil.find_difference_of_privacy(original_resp_data, replayed_resp_data)
        return is_different

def replay_with_mutation_mp(flow: http.HTTPFlow):
    if flow.request.method == "POST":
        post_url = flow.request.host + flow.request.path
        if post_url not in original_flow_recorder:
            ctx.log.error("Error, not find original flow!")
            return

        if "content-type" in dict(flow.request.headers) or "Content-Type" in dict(flow.request.headers):
            if flow.request.headers["content-type"].startswith("application/msgpack"):
                request_json_str = form_msgpack(get_req_body_content(flow))
                if not request_json_str:
                    return
                request_json = mutate.to_dict(request_json_str)
                if not isinstance(request_json, dict):
                    return

                resp_data_str = form_msgpack(flow.response.get_content())

                ctx.log.warn("Replaying post " + post_url)
                record_dir = post_url.replace("/", "]")
                record_dir = post_url.replace("?", "-")
                record_dir = os.path.join("test", record_dir)
                myutil.write_content_to_file(record_dir, "original_json.json", request_json_str)
                myutil.write_content_to_file(record_dir, "original_traffic.json", resp_data_str)

                mutated_json_values = mutate.mutate_json(request_json, 1)

                for mutated_json_value in mutated_json_values:
                    new_flow = flow.copy()
                    new_flow.request.set_text(json_to_xml(json.dumps(mutated_json_value)))
                    new_flow.request.headers["mutate"] = "True"
                    ctx.master.commands.call("replay.client", [new_flow])
            else:
                ctx.log.warn("No mutatable item detected!")

def check_mutated_replay_res_mp(mutated_flow: http.HTTPFlow):

    if mutated_flow.request.method == "POST":
        post_url = mutated_flow.request.host + mutated_flow.request.path
        record_dir = post_url.replace("/", "]")
        record_dir = os.path.join("test", record_dir)
        if post_url in original_flow_recorder:
            original_resp_data = original_flow_recorder[post_url]["resp_data"]
            mutated_resp_data_str = form_msgpack(mutated_flow.response.get_content())
            mutated_resp_data = json.loads(mutated_resp_data_str)

            post_diff = None
            if "request_data" in original_flow_recorder[post_url]:
                mutated_json = json.loads(form_msgpack(mutated_flow.request.get_content()))
                original_json = original_flow_recorder[post_url]["request_data"]
                post_diff = myutil.compare_json(original_json, mutated_json)

            is_different, resp_diff = myutil.find_difference_of_privacy(original_resp_data, mutated_resp_data)
            if is_different:
                """将新产生的结果保存到文件"""
                myutil.write_content_to_file(record_dir, post_diff + ".json", mutated_resp_data_str)
                record_str = "[POST] " + post_url + "\n"  # to add some record
                record_str += (post_diff + " " + resp_diff + "\n\n")
                myutil.append_content_to_file("test/record.txt", record_str)
                ctx.log.warn("Mutated flow: find difference, recorded")
            else:
                ctx.log.warn("Mutated flow: all the same\n")

        else:
            ctx.log.error("Bug, not find original res: " + post_url)
        pass





class TrafficFuzzer:

    def request(self, flow: http.HTTPFlow):
        pass

    def response(self, flow: http.HTTPFlow):
        request_url = None
        if flow.request.method == "GET":
            request_url = flow.request.host + flow.request.path.split("?")[0]
        elif flow.request.method == "POST":
            request_url = flow.request.host + flow.request.path
        else:
            return

        if "content-type" in dict(flow.response.headers) or "Content-Type" in dict(flow.response.headers):
            content_type = flow.response.headers["content-type"]
            if content_type.startswith("text/javascript") \
                    or content_type.startswith("application/javascript") \
                    or content_type.startswith("application/json") \
                    or content_type.startswith("text/json"):
                if not flow.request.url.endswith(".js"):
                    content = get_resp_body(flow)
                    if content:
                        myutil.append_content_to_file("response_content_type.txt", content_type + "\n")
                        json_obj = mutate.to_dict(content)
                        if not json_obj:
                            myutil.append_content_to_file("response_content_type.txt", "    Error\n")
                            # ctx.log.error("Json 解析错误，url为" + flow.request.url)
                            return
                        if not isinstance(json_obj, dict):
                            myutil.append_content_to_file("response_content_type.txt", "    Error\n")
                            # ctx.log.error("Json 解析错误，url为" + flow.request.url)
                            return

                        """
                        First, detect the existence of privacy.
                        """
                        detect_res = myutil.detect_privacy(json_obj)
                        if not detect_res:
                            return

                        #other_data_seed = judge_traffic_privacy.save_seed(json_obj) #保存重放种子库

                        if flow.is_replay == "request":
                            """
                            1. The flow is mutated.
                            2. The flow is not mutated.
                            """
                            if is_mutated_flow(flow):
                                ctx.log.warn("Mutated flow: " + flow.request.method + " " + request_url)  # 被重放的流量url
                                check_mutated_replay_res(flow)
                            else:
                                is_random = check_random_res_in_replayed_flow(flow)
                                if not is_random:
                                    """检查是否是unrelated"""
                                    if is_unrelated_request(flow.request.path):
                                        ctx.log.warn("Unrelated flow: " + flow.request.method + " " + request_url)
                                        return
                                    ctx.log.warn("Ready to replay with mutation: " + flow.request.method + " " + request_url)
                                    replay_with_mutation(flow)
                                else:
                                    ctx.log.error("Random flow: " + flow.request.method + " " + request_url)
                        else:
                            """
                            We did not replay any response, so it is a new flow.
                            1. Repeat of recorded flow
                            2. Non-repeated flow
                            """
                            if request_url in original_flow_recorder:
                                # todo: modify the implementation of this function
                                pass
                            else:
                                ctx.log.warn("Detect privacies: " + request_url + " " + str(len(detect_res)))  # 被重放的流量url
                                replay_without_mutation(flow)


            # protobuf part
            elif content_type.startswith("application/x-protobuf"):
                pbcontent_original = get_resp_body_content(flow)
                if(pbcontent_original):
                    try:
                        pbcontent = protobuf.format_pbuf(pbcontent_original)
                    except:
                        myutil.append_content_to_file("response_content_type.txt", "    Error\n") 
                        ctx.log.error("Protobuf 解析错误，url为" + flow.request.url) 
                        return
                    else:
                        myutil.append_content_to_file("response_content_type.txt", content_type + "\n")

                    #privacy detect
                    detect_pb = pb_part.detect_privacy_pb(pbcontent)
                    if not detect_pb:
                        return
                    
                    #mutate part
                    if flow.is_replay == "request":
                        if is_mutated_flow_pb(flow):
                                ctx.log.warn("Mutated flow: " + flow.request.method + " " + request_url)  # 被重放的流量url
                                check_mutated_replay_res_pb(flow)
                        else:
                            is_random = check_random_res_in_replayed_flow_pb(flow)
                            if not is_random:
                                ctx.log.warn("Ready to replay with mutation: " + flow.request.method + " " + request_url)
                                replay_with_mutation_pb(flow)
                            else:
                                ctx.log.error("Random flow: " + flow.request.method + " " + request_url)
                    else:
                        if request_url in original_flow_recorder:
                            pass
                        else:
                            ctx.log.warn("Detect privacies: " + request_url + " " + str(len(detect_pb)))  # 被重放的流量url
                            replay_without_mutation_pb(flow)

            # xml part
            elif content_type.startswith("application/xml"):
                xml_content_unform = get_resp_body(flow)
                xml_content = xml_to_json(xml_content_unform)
                if xml_content:
                    myutil.append_content_to_file("response_content_type.txt", content_type + "\n")
                    json_obj = mutate.to_dict(xml_content)
                    if not json_obj:
                        myutil.append_content_to_file("response_content_type.txt", "    Error\n")
                        return
                    if not isinstance(json_obj, dict):
                        myutil.append_content_to_file("response_content_type.txt", "    Error\n")
                        return
                
                    detect_res = myutil.detect_privacy(json_obj)
                    if not detect_res:
                        return

                    if flow.is_replay == "request":
                        if is_mutated_flow_xml(flow):
                            ctx.log.warn("Mutated flow: " + flow.request.method + " " + request_url)  
                            check_mutated_replay_res(flow)
                        else:
                            is_random = check_random_res_in_replayed_flow_xml(flow)
                            if not is_random:
                                if is_unrelated_request(flow.request.path):
                                    ctx.log.warn("Random flow: " + flow.request.method + " " + request_url)
                                    return
                                ctx.log.warn("Ready to replay with mutation: " + flow.request.method + " " + request_url)
                                replay_with_mutation_xml(flow)
                            else:
                                ctx.log.error("Random flow: " + flow.request.method + " " + request_url)
                    else:
                        if request_url in original_flow_recorder:
                            pass
                        else:
                            ctx.log.warn("Detect privacies: " + request_url + " " + str(len(detect_res)))  # 被重放的流量url
                            replay_without_mutation_xml(flow)

            # msgpack part
            elif content_type.startswith("application/msgpack"):
                mp_content_unform = get_resp_body(flow)
                content = json.dumps(mp_content_unform)
                if content:
                    myutil.append_content_to_file("response_content_type.txt", content_type + "\n")
                    json_obj = mutate.to_dict(content)
                    if not json_obj:
                        myutil.append_content_to_file("response_content_type.txt", "    Error\n")
                        return
                    if not isinstance(json_obj, dict):
                        myutil.append_content_to_file("response_content_type.txt", "    Error\n")
                        return
                
                    detect_res = myutil.detect_privacy(json_obj)
                    if not detect_res:
                        return

                    if flow.is_replay == "request":
                        if is_mutated_flow_mp(flow):
                            ctx.log.warn("Mutated flow: " + flow.request.method + " " + request_url)  
                            check_mutated_replay_res(flow)
                        else:
                            is_random = check_random_res_in_replayed_flow_mp(flow)
                            if not is_random:
                                if is_unrelated_request(flow.request.path):
                                    ctx.log.warn("Random flow: " + flow.request.method + " " + request_url)
                                    return
                                ctx.log.warn("Ready to replay with mutation: " + flow.request.method + " " + request_url)
                                replay_with_mutation_mp(flow)
                            else:
                                ctx.log.error("Random flow: " + flow.request.method + " " + request_url)
                    else:
                        if request_url in original_flow_recorder:
                            pass
                        else:
                            ctx.log.warn("Detect privacies: " + request_url + " " + str(len(detect_res)))  # 被重放的流量url
                            replay_without_mutation_mp(flow)




addons = [
    TrafficFuzzer()
]


if __name__ == "__main__":
    pass
    print(is_unrelated_request("push.kotha.im/api/register"))

