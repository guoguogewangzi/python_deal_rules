#处理snort规则文件并保存为csv
import re
import json

#"字符串"空格后面的替换为无
def tmp_replace(tmp):
    return tmp.replace(re.search(r' .*', tmp).group(0), "",1).replace("\n", '')

#readlines(),读入文件所有行，以每行为元素（字符串）形成列表
da=[]
with open("total.rules",encoding='utf-8') as f:
    da=f.readlines()

#替换每行'\n'，保存为data列表
data=[]
for line in da:
    data.append(line.replace('\n',''))


data3=[]
for data in data:

    #定义字段并取值：ps：action=""

    try:
        action = data.replace(re.search(r' .*', data).group(0), "",1).replace('\n', '')
        #print(action)
    except:
        action=None

    try:
        tmp = data.replace(re.search(r'[#a-z]+ ', data).group(0), '',1)
        proto = tmp_replace(tmp)
        # print(proto)
    except:
        proto=None

    try:
        tmp = data.replace(re.search(r'^alert [\w$_]+ ', data).group(0), '',1)
        src_ip = tmp_replace(tmp)
        #print(src_ip)
    except:
        src_ip=None

    try:
        tmp = data.replace(
            re.search(r'^alert [\w$_]+ ((((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})(\.((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})){3})|[\w$_]*) ',data).group(0), '',1)
        src_port = tmp_replace(tmp).replace(',',';')
        #print(src_port)
    except:
        src_port=None

    try:
        tmp=tmp.replace(re.search(r'([0-9]+|any) -> ',tmp).group(0),'',1)
        dest_ip=tmp_replace(tmp)
        #print(dest_ip)
    except:
        dest_ip=None

    try:
        tmp=tmp.replace(re.search(r'([\w$_]+) ',tmp).group(0),'',1)
        dest_port=tmp_replace(tmp).replace(',',';')
        #print(dest_port)
    except:
        dest_port=None

    try:
        tmp=data.replace(re.search(r'.*msg:"{',data).group(0),'{',1)
        msg=tmp.replace(re.search(r'}";.*',tmp).group(0),'}')
        msg=eval(msg)
        family=msg['family']
        behavior=msg['behavior']
        description=msg['description']
        sign_source=msg['sign_source']
        author=msg['author']
        threat_judge=msg['threat_judge']
        attack_phase=msg['attack_phase']
        apt_org=msg['apt_org']
        extract_data=msg['extract_date']
        attack_direction=str(msg['attack_direction']).replace(',',';')
        remarks=msg['remarks']
        cve_number=msg['cve_number']
        threat_level=msg['threat_level']
        threat_type=str(msg['threat_type']).replace(',',';')
        id=msg['id']
        refer=msg['refer']
    except:
        family=None
        behavior=None
        description=None
        sign_source=None
        author=None
        threat_judge=None
        attack_phase=None
        apt_org=None
        extract_data=None
        attack_direction=None
        remarks=None
        cve_number=None
        threat_level=None
        threat_type=None
        id=None
        refer=None

    try:
        tmp=data.replace(re.search(r'.*}"; ',data).group(0),'')
        payload=tmp.replace(re.search(r' metadata:.*;',tmp).group(0),'').replace('\n','').replace(',',';')
        #print(payload)
    except:
        payload=None

    try:
        classtype=re.search(r'classtype:(.*?\;)',data).group(0)
        #print(classtype)
    except:
        classtype=None

    try:
        sid=re.search(r'id:(.*?\;)',data).group(0)
        #print(sid)
    except:
        sid=None
    try:
        rev=re.search(r'rev:(.*?\;)',data).group(0)
        #print(rev)
    except:
        rev=None

    metadata=""
    while True:
        try:
            metadata += re.search(r'metadata:(.*?\;)', data).group(0)
            data = data.replace(re.search(r'metadata:(.*?\;)', data).group(0), '')
        except:
            break
    metadata=metadata.replace(',',';')
    #取值结束

    #变成一个字典data2
    data2 = dict(
        action=action,
        proto=proto,
        src_ip=src_ip,
        src_port=src_port,
        dest_ip=dest_ip,
        dest_port=dest_port,
        family=family,
        behavior=behavior,
        description=description,
        sign_source=sign_source,
        author=author,
        threat_judge=threat_judge,
        attack_phase=attack_phase,
        apt_org=apt_org,
        extract_date=extract_data,
        attack_direction=attack_direction,
        remarks=remarks,
        cve_number=cve_number,
        threat_level=threat_level,
        threat_type=threat_type,
        id=id,
        refer=refer,
        payload=payload,
        classtype=classtype,
        sid=sid,
        rev=rev,
        metadata=metadata
    )
    #data2字典保存在data3列表中
    data3.append(data2)

#取key->列表，保存在data4中
data4=[]
key=list(data3[0].keys())
data4.append(key)

#取value->列表，保存在data4中
for line in data3:
    value=list(line.values())
    data4.append(value)

#将data4中的每个列表元素拼接成字符串
data5=[]
for line in data4:
    data5.append(",".join('%s' % id  for id in line))

#根据data5列表按行写文件
with open('rules.csv','w') as f:
    for line in data5:
        f.write(line+'\n')





