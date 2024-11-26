import json
from pprint import pprint
with open('uaf_true.json', 'r') as json_file:
    file = (json.load(json_file))
    idx = set()
    pattern = {}
    for i, instruction in enumerate(file):
        if instruction["operation"].startswith("48 89"):
            for j, nxt in enumerate(file[i+1:]):
                if nxt["operation"].startswith("e8"):
                    if nxt["index"] in idx or instruction["index"] in idx:
                        break
                    idx.add(instruction["index"])
                    idx.add(nxt["index"])
                    if len(nxt["registers"]["rdi"]) > 5:
                        pattern[nxt["registers"]["rdi"]] = nxt["index"]
                continue
        continue
    pprint(pattern)
    uaf = []
    for add, ind in pattern.items():
        # find if address add is used in any other instruction after index ind
        for instruction in file[ind+1:]:
            if add in instruction["memory_operation"]["details"]:
                uaf.append(add)
                break
            continue
            




