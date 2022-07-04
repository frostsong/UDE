import myutil
import os
import random
import json
import chardet
import judge_traffic_privacy
from mitmproxy import http
from mitmproxy import ctx
import mutate
from google.protobuf import json_format

def detect_privacy_pb(pbcontent):
    f = pbcontent.splitlines()
    res = []
    detect_res = []
    colon = ":"
    for line in f:
        if colon and "com" and "/" in line:
            try:
                pf_middle_line = line.split(colon,1)
                pf_middle_line = pf_middle_line[1].split("/",1)
                pf_middle_line = pf_middle_line[1].split(".")
            except:
                pass
            else:
                for ori_word in pf_middle_line:
                    judge_res = judge_traffic_privacy.judge_key(ori_word)
                    if judge_res[1]:
                        detect_res.append(judge_res)
            # try:
            #     pfvalues = pf_middle_line[1].split(".")
            # except:
            #     pass
            # else:
            #     for pfvalue in pfvalues:   
            #          judge_res = judge_traffic_privacy.judge_key(pfvalue)
            #          if judge_res[1]:
            #              detect_res.append(judge_res)
                    
    for privacy_key, dp_res in detect_res:
        if privacy_key not in res:
            res.append(privacy_key)
    return res







if __name__ == "__main__":
    response = chardet.detect(b'\x1a3{"lat":13.939666446460503,"lng":100.15095982700586}')
    a = b'\x1a3{"lat":13.939666446460503,"lng":100.15095982700586}'
    print(response)
    print(a.decode('utf8'))