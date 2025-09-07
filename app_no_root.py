import threading
import jwt
import random
from threading import Thread
import json
import requests
import google.protobuf
from protobuf_decoder.protobuf_decoder import Parser
import json

import datetime
from datetime import datetime
from google.protobuf.json_format import MessageToJson
import my_message_pb2
import data_pb2
import base64
import logging
import re
import socket
from google.protobuf.timestamp_pb2 import Timestamp
import jwt_generator_pb2
import os
import binascii
import sys
# import psutil (disabled for no-root)
import MajorLoginRes_pb2
from time import sleep
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import time
from important_zitado import*
tempid = None
sent_inv = False
start_par = False
nameinv = "none"
idinv = 0
senthi = False
statusinfo = None
tempdata = None
data22 = None
def encrypt_packet(plain_text, key, iv):
    plain_text = bytes.fromhex(plain_text)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()
    
def gethashteam(hexxx):
    a = zitado_get_proto(hexxx)
    if not a:
        raise ValueError("Invalid hex format or empty response from zitado_get_proto")
    data = json.loads(a)
    return data['5']['7']
def getownteam(hexxx):
    a = zitado_get_proto(hexxx)
    if not a:
        raise ValueError("Invalid hex format or empty response from zitado_get_proto")
    data = json.loads(a)
    return data['5']['1']

def get_player_status(packet):
    json_result = get_available_room(packet)
    parsed_data = json.loads(json_result)

    if "5" not in parsed_data or "data" not in parsed_data["5"]:
        return "ONLINE"

    json_data = parsed_data["5"]["data"]

    if "1" not in json_data or "data" not in json_data["1"]:
        return "ONLINE"

    data = json_data["1"]["data"]

    if "3" not in data:
        return "ONLINE"

    status_data = data["3"]

    if "data" not in status_data:
        return "ONLINE"

    status = status_data["data"]

    if status == 1:
        return "SOLO"
    
    if status == 2:
        if "9" in data and "data" in data["9"]:
            group_count = data["9"]["data"]
            countmax1 = data["10"]["data"]
            countmax = countmax1 + 1
            return f"INSQUAD ({group_count}/{countmax})"

        return "INSQUAD"
    
    if status in [3, 5]:
        return "INGAME"
    if status == 4:
        return "IN ROOM"
    
    if status in [6, 7]:
        return "IN SOCIAL ISLAND MODE .."

    return "NOTFOUND"
def get_idroom_by_idplayer(packet):
    json_result = get_available_room(packet)
    parsed_data = json.loads(json_result)
    json_data = parsed_data["5"]["data"]
    data = json_data["1"]["data"]
    idroom = data['15']["data"]
    return idroom
    
    return "NOTFOUND"
def generate_random_color():
	color_list = [
    "[00FF00][b][c]",
    "[FFDD00][b][c]",
    "[3813F3][b][c]",
    "[FF0000][b][c]",
    "[0000FF][b][c]",
    "[FFA500][b][c]",
    "[DF07F8][b][c]",
    "[11EAFD][b][c]",
    "[DCE775][b][c]",
    "[A8E6CF][b][c]",
    "[7CB342][b][c]",
    "[FF0000][b][c]",
    "[FFB300][b][c]",
    "[90EE90][b][c]"
]
	random_color = random.choice(color_list)
	return  random_color

def fix_num(num):
    fixed = ""
    count = 0
    num_str = str(num)  # Convert the number to a string

    for char in num_str:
        if char.isdigit():
            count += 1
        fixed += char
        if count == 3:
            fixed += "[c]"
            count = 0  
    return fixed


def fix_word(num):
    fixed = ""
    count = 0
    
    for char in num:
        if char:
            count += 1
        fixed += char
        if count == 3:
            fixed += "[c]"
            count = 0  
    return fixed
    
def check_banned_status(player_id):
   
    url = f"https://wlx-ban-check.vercel.app/get_region?uid={player_id}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            return data  
        else:
            return {"error": f"Failed to fetch data. Status code: {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}
        
def send_vistttt(uid):

    message = (
        f"[C][B][FF0000]________________________\n"
        f" Wrong ID ..\n"
        f" Please Check Again\n"
        f"________________________"
    )

    info_response = newinfo(uid)
    print(info_response)
    if info_response['status'] == "ok":
        requests.get(f"http://147.93.123.53:50099/{uid}")
        message = (
            f"{generate_random_color()}________________________\n\n"
            f" Visit Sent To ID : {fix_num(uid)}..\n"

            f"________________________"
        )

    return message        


def rrrrrrrrrrrrrr(number):
    if isinstance(number, str) and '***' in number:
        return number.replace('***', '106')
    return number
def newinfo(uid):
	try:
		response = requests.get(f"http://147.93.123.53:5002/{uid}")
		
		if response.status_code == 200:
			response = response.json()
			basic_info = response['basicinfo'][0]
			clan_info = response['claninfo'][0]
			
			if clan_info['clanid'] == 0:
				clan_info = "false"
				clan_admin_info = "false"
			else:
				clan_admin_info = response['clanadmin'][0]
				
			info = {
				'basic_info':basic_info,
				'clan_info':clan_info,
				'clan_admin':clan_admin_info
				}
			return {"status":"ok","info":info}
		else:
			return {"status":"wrong_id"}
	except Exception as e:
		return e
	
def send_likes(uid):
	likes_api_response = requests.get(f"http://147.93.123.53:5008/like?uid={uid}&key=22")
	message = (f"[C][B][FF0000]________________________\n"
f" Wrong ID .......\n"
f" Please Check Again\n"
f"________________________")
	if likes_api_response.status_code == 200:
		api_json_response = likes_api_response.json()
		player_level = api_json_response['level']
		likes_added = api_json_response['likes_added']
		likes_after = api_json_response['likes_after']
		likes_before = api_json_response['likes_before']
		player_name = api_json_response['name']
		region = api_json_response['region']
		message = (f"{generate_random_color()}________________________\n"
f" Likes Status :\n"
f" LIKES SENT !\n\n"
f" PLAYER NAME : {player_name}\n"
f" PLAYER LEVEL : {player_level}\n"
f" LIKES ADDED : {likes_added}\n"
f" LIKES BEFORE : {likes_before}\n"
f" LIKES AFTER : {likes_after}\n"

f"________________________")
		
		return {"status":"ok","message":message}
	else:
		return {"status":"failed","message":message}
		
def Encrypt(number):
    number = int(number)  # تحويل الرقم إلى عدد صحيح
    encoded_bytes = []    # إنشاء قائمة لتخزين البايتات المشفرة

    while True:  # حلقة تستمر حتى يتم تشفير الرقم بالكامل
        byte = number & 0x7F  # استخراج أقل 7 بتات من الرقم
        number >>= 7  # تحريك الرقم لليمين بمقدار 7 بتات
        if number:
            byte |= 0x80  # تعيين البت الثامن إلى 1 إذا كان الرقم لا يزال يحتوي على بتات إضافية

        encoded_bytes.append(byte)
        if not number:
            break  # التوقف إذا لم يتبقى بتات إضافية في الرقم

    return bytes(encoded_bytes).hex()
def send_spam(uid):
    message = (
        f"[C][B][FF0000]-----------------------------------\n"
        f" Wrong ID ..\n"
        f" Please Check Again\n"
        f" DEV BOT @wlx_demon\n"
        f"-----------------------------------"
    )


    info_response = newinfo(uid)
    print(info_response)
    if info_response['status'] == "ok":
        requests.get(f"http://ffwlxd-add-api.vercel.app/request?api_key=wlx&uid={uid}")
        message = (
            f"{generate_random_color()}-----------------------------------\n"
            f" Spam Sent To ID : {fix_num(uid)}..\n"
            f" DEV BOT:  WLX DEMON\n"
            f"-----------------------------------"
        )

    return message

def get_random_avatar():
	avatar_list = ['902000061','902000060','902000064','902000065','902000066','902000066','902000074','902000075','902000077','902000078','902000084','902000085','902000087','902000091','902000094','902000306']
	random_avatar = random.choice(avatar_list)
	return  random_avatar


def remove_user(uid):
	requests.get(f"http://ffwlxd-add-api.vercel.app/remove/{uid}?key=ffwlx")

def get_time(uid):
	r = requests.get(f"https://ffwlxd-time-api.vercel.app/get_time/{uid}")
	try:
		response = r
		if "permanent" in response.text:
			time = "Permanent"
			return {"status":"ok","time":time}
		elif "UID not found" in response.text:
			remove_user(uid)
			return {"status":"bad","time":"Expired"}
		else:
			try:
				data = response.json()['remaining_time']
				days = data['days']
				hours = data['hours']
				minutes = data['minutes']
				seconds = data['seconds']
				time = (

				f"{days} Days\n"
				f"{hours} Hours\n"
				f"{minutes} Minutes\n"
				f"{seconds} Seconds\n")
				return {"status":"ok","time":time}
			except Exception as e:
				print(e)
	except Exception as e:
		print(e)



class FF_CLIENT(threading.Thread):
    def __init__(self, id, password):
        self.id = id
        self.password = password
        self.key = None
        self.iv = None
        self.get_tok()

    def GenResponsMsg(self, Msg, Enc_Id):
        root = data_pb2.Root()
        root.field1 = 1
        nested_object = root.field2
        nested_object.field1 = 1878153216
        nested_object.field2 = Enc_Id
        nested_object.field3 = 2
        nested_object.field4 = Msg
        nested_object.field5 = int(datetime.now().timestamp())
        nested_details = nested_object.field9
        nested_details.field1 = "bot"
        nested_details.field2 = 902046038
        nested_details.field4 = 231
        nested_details.field8 = "Bott"
        nested_details.field10 = 2
        nested_options = nested_object.field13
        nested_options.field1 = "https://graph.facebook.com/v9.0/147045590125499/picture?width=160&height=160"
        nested_options.field2 = 1
        nested_options.field3 = 1
        serialized_data = root.SerializeToString()
        packet = serialized_data.hex()
        header_length = len(self.nmnmmmmn(packet)) // 2
        header_length_hex = dec_to_hex(header_length)

        if len(header_length_hex) == 2:
            final_packet = "1215000000" + header_length_hex + self.nmnmmmmn(packet)
        elif len(header_length_hex) == 3:
            final_packet = "121500000" + header_length_hex + self.nmnmmmmn(packet)
        elif len(header_length_hex) == 4:
            final_packet = "12150000" + header_length_hex + self.nmnmmmmn(packet)
        elif len(header_length_hex) == 5:
            final_packet = "1215000" + header_length_hex + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)

    def connect(self, tok, host, port, packet, key, iv):
        global clients
        clients = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        port = int(port)
        clients.connect((host, port))
        clients.send(bytes.fromhex(tok))

        while True:
            data = clients.recv(9999)
            if data == b"":
                print("Connection closed by remote host")
                break
            
def get_available_room(input_text):
    try:
        parsed_results = Parser().parse(input_text)
        parsed_results_objects = parsed_results
        parsed_results_dict = parse_results(parsed_results_objects)
        json_data = json.dumps(parsed_results_dict)
        return json_data
    except Exception as e:
        print(f"error {e}")
        return None

def parse_results(parsed_results):
    result_dict = {}
    for result in parsed_results:
        field_data = {}
        field_data["wire_type"] = result.wire_type
        if result.wire_type == "varint":
            field_data["data"] = result.data
        if result.wire_type == "string":
            field_data["data"] = result.data
        if result.wire_type == "bytes":
            field_data["data"] = result.data
        elif result.wire_type == "length_delimited":
            field_data["data"] = parse_results(result.data.results)
        result_dict[result.field] = field_data
    return result_dict

def dec_to_hex(ask):
    ask_result = hex(ask)
    final_result = str(ask_result)[2:]
    if len(final_result) == 1:
        final_result = "0" + final_result
    return final_result

def encrypt_message(plaintext):
    key = b'Yg&tc%DEuh6%Zc^8'
    iv = b'6oyZDr22E3ychjM%'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(plaintext, AES.block_size)
    encrypted_message = cipher.encrypt(padded_message)
    return binascii.hexlify(encrypted_message).decode('utf-8')

def encrypt_api(plain_text):
    plain_text = bytes.fromhex(plain_text)
    key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()

def extract_jwt_from_hex(hex):
    byte_data = binascii.unhexlify(hex)
    message = jwt_generator_pb2.wlxd()
    message.ParseFromString(byte_data)
    json_output = MessageToJson(message)
    token_data = json.loads(json_output)
    return token_data
    

def format_timestamp(timestamp):
    return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')

def restart_program():
    print("Restart requested. Please restart manually.")
    sys.exit(0)
          
class FF_CLIENT(threading.Thread):
    def __init__(self, id, password):
        super().__init__()
        self.id = id
        self.password = password
        self.key = None
        self.iv = None
        self.get_tok()

    def parse_my_message(self, serialized_data):
        try:
            MajorLogRes = MajorLoginRes_pb2.MajorLoginRes()
            MajorLogRes.ParseFromString(serialized_data)
            key = MajorLogRes.ak
            iv = MajorLogRes.aiv
            if isinstance(key, bytes):
                key = key.hex()
            if isinstance(iv, bytes):
                iv = iv.hex()
            self.key = key
            self.iv = iv
            print(f"Key: {self.key} | IV: {self.iv}")
            return self.key, self.iv
        except Exception as e:
            print(f"{e}")
            return None, None

    def nmnmmmmn(self, data):
        key, iv = self.key, self.iv
        try:
            key = key if isinstance(key, bytes) else bytes.fromhex(key)
            iv = iv if isinstance(iv, bytes) else bytes.fromhex(iv)
            data = bytes.fromhex(data)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            cipher_text = cipher.encrypt(pad(data, AES.block_size))
            return cipher_text.hex()
        except Exception as e:
            print(f"Error in nmnmmmmn: {e}")

    def spam_room(self, idroom, idplayer):
        fields = {
        1: 78,
        2: {
            1: int(idroom),
            2: "[FF0000]ＦＦＷＬＸＤㅤᴮᴼᵀ",
            4: 330,
            5: 6000,
            6: 201,
            10: int(get_random_avatar()),
            11: int(idplayer),
            12: 1
        }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0E15000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "0E1500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "0E150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0E15000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def send_squad(self, idplayer):
        fields = {
            1: 33,
            2: {
                1: int(idplayer),
                2: "ME",
                3: 1,
                4: 1,
                7: 330,
                8: 19459,
                9: 100,
                12: 1,
                16: 1,
                17: {
                2: 94,
                6: 11,
                8: "1.109.5",
                9: 3,
                10: 2
                },
                18: 201,
                23: {
                2: 1,
                3: 1
                },
                24: int(get_random_avatar()),
                26: {},
                28: {}
            }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def start_autooo(self):
        fields = {
        1: 9,
        2: {
            1: 11313318902
        }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def invite_skwad(self, idplayer):
        fields = {
        1: 2,
        2: {
            1: int(idplayer),
            2: "IND",
            4: 1
        }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def request_skwad(self, idplayer):
        fields = {
        1: 33,
        2: {
            1: int(idplayer),
            2: "IND",
            3: 1,
            4: 1,
            7: 330,
            8: 19459,
            9: 100,
            12: 1,
            16: 1,
            17: {
            2: 94,
            6: 11,
            8: "1.109.5",
            9: 3,
            10: 2
            },
            18: 201,
            23: {
            2: 1,
            3: 1
            },
            24: int(get_random_avatar()),
            26: {},
            28: {}
        }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def skwad_maker(self):
        fields = {
        1: 1,
        2: {
            2: "\u0001",
            3: 1,
            4: 1,
            5: "en",
            9: 1,
            11: 1,
            13: 1,
            14: {
            2: 5756,
            6: 11,
            8: "1.109.5",
            9: 3,
            10: 2
            },
        }
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def changes(self, num):
        fields = {
        1: 17,
        2: {
            1: 11313318902,
            2: 1,
            3: int(num),
            4: 62,
            5: "\u001a",
            8: 5,
            13: 329
        }
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
   
    def leave_s(self):
        fields = {
        1: 7,
        2: {
            1: 11313318902
        }
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def leave_room(self, idroom):
        fields = {
        1: 6,
        2: {
            1: int(idroom)
        }
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0E15000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "0E1500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "0E150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0E15000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def stauts_infoo(self, idd):
        fields = {
        1: 7,
        2: {
            1: 11313318902
        }
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
        #print(Besto_Packet)
    def GenResponsMsg(self, Msg, Enc_Id):
        fields = {
 1: 1,
 2: {
  1: 3557944186,
  2: Enc_Id,
  3: 2,
  4: Msg,
  5: int(datetime.now().timestamp()),
  9: {
   
   2: int(get_random_avatar()),
   3: 901041021,
   4: 330,
   
   10: 1,
   11: 155
  },
  10: "en",
  13: {
   1: "https://graph.facebook.com/v9.0/104076471965380/picture?width=160&height=160",
   2: 1,
   3: 1
  }
 },
 14: ""
}

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "1215000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "121500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "12150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "1215000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def createpacketinfo(self, idddd):
        ida = Encrypt(idddd)
        packet = f"080112090A05{ida}1005"
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0F15000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "0F1500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "0F150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0F15000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def accept_sq(self, hashteam, idplayer, ownerr):
        fields = {
        1: 4,
        2: {
            1: int(ownerr),
            3: int(idplayer),
            4: "\u0001\u0007\t\n\u0012\u0019\u001a ",
            8: 1,
            9: {
            2: 1393,
            4: "wW_T",
            6: 11,
            8: "1.109.5",
            9: 3,
            10: 2
            },
            10: hashteam,
            12: 1,
            13: "en",
            16: "OR"
        }
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)

    def sockf1(self, tok, host, port, packet, key, iv):
        global socket_client
        global sent_inv
        global tempid
        global start_par
        global clients

        global nameinv
        global idinv
        global senthi
        global statusinfo
        global tempdata
        global data22
        socket_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        port = int(port)

        socket_client.connect((host,port))
        print(f" Con port {port} Host {host} ")
        print(tok)
        socket_client.send(bytes.fromhex(tok))
        while True:
            data2 = socket_client.recv(9999)
            print(data2)
            if "0500" in data2.hex()[0:4] and len(data2.hex()) > 30:
                if sent_inv == True:
                    accept_packet = f'08{data2.hex().split("08", 1)[1]}'
                    print(accept_packet)
                    print(tempid)
                    aa = gethashteam(accept_packet)
                    ownerid = getownteam(accept_packet)
                    print(ownerid)
                    print(aa)
                    ss = self.accept_sq(aa, tempid, int(ownerid))
                    socket_client.send(ss)
                    sleep(1)
                    startauto = self.start_autooo()
                    socket_client.send(startauto)
                    start_par = False
                    sent_inv = False
            if "0600" in data2.hex()[0:4] and len(data2.hex()) > 700:
                    accept_packet = f'08{data2.hex().split("08", 1)[1]}'
                    kk = get_available_room(accept_packet)
                    parsed_data = json.loads(kk)
                    print(parsed_data)
                    idinv = parsed_data["5"]["data"]["1"]["data"]
                    nameinv = parsed_data["5"]["data"]["3"]["data"]
                    senthi = True
            if "0f00" in data2.hex()[0:4]:
                packett = f'08{data2.hex().split("08", 1)[1]}'
                print(packett)
                kk = get_available_room(packett)
                parsed_data = json.loads(kk)
                idinv = parsed_data["1"]["data"]
                asdj = parsed_data["2"]["data"]
                if asdj == 15:
                    tempdata = get_player_status(packett)
                    if tempdata == "IN ROOM":
                        data22 = packett
                    print(data2.hex())
                    print(tempdata)
                    statusinfo = True
                else:
                    pass
                
                    

                    
                
                    
            if data2 == b"":
                
                print("Connection closed by remote host")
                restart_program()
                break
    
    def connect(self, tok, host, port, packet, key, iv):
        global clients
        global socket_client
        global sent_inv
        global tempid
        global start_par
        global nameinv
        global idinv
        global senthi
        global statusinfo
        global tempdata
        global data22
        clients = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        port = int(port)
        clients.connect((host, port))
        clients.send(bytes.fromhex(tok))
        thread = threading.Thread(
            target=self.sockf1, args=(tok, "98.98.162.73", 39698, "anything", key, iv)
        )
        threads.append(thread)
        thread.start()

        while True:
            data = clients.recv(9999)

            if data == b"":
                print("Connection closed by remote host")
                break
                print(f"Received data: {data}")
            
            if senthi == True:
                
                clients.send(
                        self.GenResponsMsg(
                            f"""[C][B]What\'s Up {nameinv}

Iam [ff000000]ＦＦＷＬＸＤㅤᴮᴼᵀ[ffffff] And Im Here To Serve You.

Send [00ff00]/help [ffffff]So You Can Get To Know My Commands!.

Bot Made By [00ff00]ＦＦＷＬＸＤ.""", idinv
                        )
                )
                senthi = False
            
            
                
            if "1200" in data.hex()[0:4]:
               
                json_result = get_available_room(data.hex()[10:])
                print(data.hex())
                parsed_data = json.loads(json_result)
                uid = parsed_data["5"]["data"]["1"]["data"]
                if "8" in parsed_data["5"]["data"] and "data" in parsed_data["5"]["data"]["8"]:
                    uexmojiii = parsed_data["5"]["data"]["8"]["data"]
                    if uexmojiii == "DefaultMessageWithKey":
                        pass
                    else:
                        clients.send(
                            self.GenResponsMsg(
                                f"[b][C][00FFFF]Welcome!\nsir tt7wa hhhhhhhhhhh", uid
                            )
                        )
                else:
                    pass  


                    
                


            if "1200" in data.hex()[0:4] and b"/admin" in data:
                i = re.split("/admin", str(data))[1]
                if "***" in i:
                    i = i.replace("***", "106")
                sid = str(i).split("(\\x")[0]
                json_result = get_available_room(data.hex()[10:])
                
                parsed_data = json.loads(json_result)
                uid = parsed_data["5"]["data"]["1"]["data"]
                clients.send(
                    self.GenResponsMsg(
                        f"""[C][B]

I Heard You Wanna See Who\'s The Admins?

I Feel Like You Wanna Buy Admin Too!

Or At Least You Wanna Buy A Server With Your Name

Right?, Well You Can!

Only Contact [00ff00]@wlx_demon![ffffff]


Also, You Can Send [00ff00]/help [ffffff]So You Can Get To Know My Commands!.

Bot Made By [00ff00] ＦＦＷＬＸＤ .""", uid
                    )
                )
            

            if "1200" in data.hex()[0:4] and b"/fs" in data:
                i = re.split("/fs", str(data))[1]
                if "***" in i:
                    i = i.replace("***", "106")
                sid = str(i).split("(\\x")[0]
                json_result = get_available_room(data.hex()[10:])
                parsed_data = json.loads(json_result)
                
                iddd = parsed_data["5"]["data"]["1"]["data"]
                tempid = iddd
                invskwad = self.request_skwad(iddd)
                socket_client.send(invskwad)
                sent_inv = True
                # time.sleep(3)
                # startauto = self.start_auto()
                # socket_client.send(startauto)
                
                
                
                uid = parsed_data["5"]["data"]["1"]["data"]
                clients.send(
                    self.GenResponsMsg(
                        f"[C][B][00ff00]Started Sucessfully ! ", uid
                    )
                )
            if "1200" in data.hex()[0:4] and b"/5s" in data:
                i = re.split("/5s", str(data))[1]
                if "***" in i:
                    i = i.replace("***", "106")
                sid = str(i).split("(\\x")[0]
                json_result = get_available_room(data.hex()[10:])
                parsed_data = json.loads(json_result)
                packetmaker = self.skwad_maker()
                socket_client.send(packetmaker)
                
                sleep(1)
                packetfinal = self.changes(4)
                room_data = None
                if b'(' in data:
                    split_data = data.split(b'/5s')
                    if len(split_data) > 1:
                        room_data = split_data[1].split(b'(')[0].decode().strip().split()
                        if room_data:
                        	iddd= room_data[0]
                        else:
                        	uid = parsed_data["5"]["data"]["1"]["data"]
                        	iddd=parsed_data["5"]["data"]["1"]["data"]
                
                
                socket_client.send(packetfinal)
                invitess = self.invite_skwad(iddd)
                socket_client.send(invitess)
                if uid:
	                clients.send(
	                    self.GenResponsMsg(
	                        f"[C][B][00ff00]- AcCept The Invite QuickLy ! ", uid
	                    )
	                )
                sleep(5)
                leavee = self.leave_s()
                socket_client.send(leavee)
                
                clients.send(
                    self.GenResponsMsg(
                        f"[C][B] [FF00FF]send succes !", uid
                    )
                )       
            if "1200" in data.hex()[0:4] and b"/6s" in data:
                i = re.split("/6s", str(data))[1]
                if "***" in i:
                    i = i.replace("***", "106")
                sid = str(i).split("(\\x")[0]
                json_result = get_available_room(data.hex()[10:])
                parsed_data = json.loads(json_result)
                packetmaker = self.skwad_maker()
                socket_client.send(packetmaker)
                sleep(1)
                packetfinal = self.changes(5)
                room_data = None
                if b'(' in data:
                    split_data = data.split(b'/6s')
                    if len(split_data) > 1:
                        room_data = split_data[1].split(b'(')[0].decode().strip().split()
                        if room_data:
                        	iddd= room_data[0]
                        else:
                        	uid = parsed_data["5"]["data"]["1"]["data"]
                        	iddd=parsed_data["5"]["data"]["1"]["data"]
                socket_client.send(packetfinal)            
                invitess = self.invite_skwad(iddd)
                socket_client.send(invitess)
                if uid:
	                clients.send(
	                    self.GenResponsMsg(
	                        f"[C][B][00ff00]- AcCept The Invite QuickLy ! ", uid
	                    )
	                )
                sleep(5)
                leavee = self.leave_s()
                socket_client.send(leavee)
                uid = parsed_data["5"]["data"]["1"]["data"]
                clients.send(
                    self.GenResponsMsg(
                        f"[C][B] [FF00FF]send succes !", uid
                    )
                )  
            if "1200" in data.hex()[0:4] and b"/status" in data:
                i = re.split("/status", str(data))[1]
                if "***" in i:
                    i = i.replace("***", "106")
                sid = str(i).split("(\\x")[0]
                json_result = get_available_room(data.hex()[10:])
                parsed_data = json.loads(json_result)
                split_data = re.split(rb'/status', data)
                room_data = split_data[1].split(b'(')[0].decode().strip().split()
                player_id = room_data[0]
                uid = parsed_data["5"]["data"]["1"]["data"]

                packetmaker = self.createpacketinfo(player_id)
                socket_client.send(packetmaker)
                sleep(1)
                if statusinfo == True:
                    print(tempdata)
                    clients.send(
                        self.GenResponsMsg(
                            f"[b][C][00FFFF]{tempdata}", uid
                        )
                    )  
                
             
            if "1200" in data.hex()[0:4] and b"/inv" in data:
                i = re.split("/inv", str(data))[1]
                if "***" in i:
                    i = i.replace("***", "106")
                sid = str(i).split("(\\x")[0]
                json_result = get_available_room(data.hex()[10:])
                parsed_data = json.loads(json_result)
                split_data = re.split(rb'/inv', data)
                room_data = split_data[1].split(b'(')[0].decode().strip().split()
                iddd = room_data[0]
                numsc1 = room_data[1]
                numsc = int(numsc1) - 1
                uid = parsed_data["5"]["data"]["1"]["data"]
                if int(numsc1) < 3 or int(numsc1) > 6:
                    clients.send(
                        self.GenResponsMsg(
                            f"[C][B][FF0000] Usage : /inv <uid> <Squad Type>\n[ffffff]Example : \n/inv 12345678 4\n/inv 12345678 5", uid
                        )
                    )
                else:
                    packetmaker = self.skwad_maker()
                    socket_client.send(packetmaker)
                    sleep(1)
                    packetfinal = self.changes(int(numsc))
                    socket_client.send(packetfinal)
                    
                    invitess = self.invite_skwad(iddd)
                    socket_client.send(invitess)
                    iddd1 = parsed_data["5"]["data"]["1"]["data"]
                    invitessa = self.invite_skwad(iddd1)
                    socket_client.send(invitessa)
                    clients.send(
	                    self.GenResponsMsg(
	                        f"[C][B][00ff00]- AcCept The Invite QuickLy ! ", uid
	                    )
	                )
                    sleep(5)
                    leavee = self.leave_s()
                    socket_client.send(leavee)
                    
            if "1200" in data.hex()[0:4] and b"/room" in data:
                i = re.split("/room", str(data))[1]
                if "***" in i:
                    i = i.replace("***", "106")
                sid = str(i).split("(\\x")[0]
                json_result = get_available_room(data.hex()[10:])
                parsed_data = json.loads(json_result)
                uid = parsed_data["5"]["data"]["1"]["data"]
                split_data = re.split(rb'/room', data)
                room_data = split_data[1].split(b'(')[0].decode().strip().split()
                player_id = room_data[0]
                if "***" in player_id:
                    player_id = rrrrrrrrrrrrrr(player_id)
                packetmaker = self.createpacketinfo(player_id)
                socket_client.send(packetmaker)
                sleep(1)
                if tempdata == "IN ROOM":
                    room_id = get_idroom_by_idplayer(data22)
                    packetspam = self.spam_room(room_id, player_id)
                    print(packetspam.hex())
                    clients.send(
	                    self.GenResponsMsg(
	                        f"[C][B][00ff00]- Spam Started for uid {fix_num(player_id)} ! ", uid
	                    )
	                )
	                
                    for _ in range(25):
                        print(" sending spam to "+player_id)
                        threading.Thread(target=socket_client.send, args=(packetspam,)).start()
                    #socket_client.send(packetspam)
                    
                    
                    
                    clients.send(
                        self.GenResponsMsg(
                            f"[C][B] [00FF00]Done Spam Sent !", uid
                        )
                    )
                else:
                    clients.send(
                        self.GenResponsMsg(
                            f"[C][B] [FF00FF]The player is not in room", uid
                        )
                    )      
            

            
            

            if "1200" in data.hex()[0:4] and b"WELCOME TO FFWLX BOT" in data:
            	pass
            else:
             
	            if "1200" in data.hex()[0:4] and b"/spam" in data:

	                command_split = re.split("/spam", str(data))
	                if len(command_split) > 1:
	                    player_id = command_split[1].split('(')[0].strip()
	                    print(f"Sending Spam To {player_id}")
	                    json_result = get_available_room(data.hex()[10:])
	                    parsed_data = json.loads(json_result)
	                    uid = parsed_data["5"]["data"]["1"]["data"]
	                    clients.send(
	                    self.GenResponsMsg(
	                        f"{generate_random_color()}Okay Sir, Please Wait..", uid
	                    )
	                )
	                    
	                    message = send_spam(player_id)
	                    print(message)
	                    json_result = get_available_room(data.hex()[10:])
	                    parsed_data = json.loads(json_result)
	                    uid = parsed_data["5"]["data"]["1"]["data"]
	                    
	                    clients.send(self.GenResponsMsg(message, uid))
	            if "1200" in data.hex()[0:4] and b"/vist" in data:

	                command_split = re.split("/vist", str(data))
	                if len(command_split) > 1:
	                    player_id = command_split[1].split('(')[0].strip()

	                    print(f"[C][B]Sending vist To {player_id}")
	                    json_result = get_available_room(data.hex()[10:])
	                    parsed_data = json.loads(json_result)
	                    uid = parsed_data["5"]["data"]["1"]["data"]
	                    clients.send(
	                    self.GenResponsMsg(
	                        f"{generate_random_color()}Okay Sir, Please Wait..", uid
	                    )
	                )
	                    
	                    message = send_vistttt(player_id)
	                    json_result = get_available_room(data.hex()[10:])
	                    parsed_data = json.loads(json_result)
	                    uid = parsed_data["5"]["data"]["1"]["data"]
	                    
	                    clients.send(self.GenResponsMsg(message, uid))	                    
	                    
	            if "1200" in data.hex()[0:4] and b"/info" in data:
	                command_split = re.split("/info", str(data))
	                if len(command_split) > 1:
	                    json_result = get_available_room(data.hex()[10:])
	                    parsed_data = json.loads(json_result)
	                    sender_id = parsed_data["5"]["data"]["1"]["data"]
	                    sender_name = parsed_data['5']['data']['9']['data']['1']['data']
	                    uid = command_split[1].split("\\x")[0].strip()
	                    uid = command_split[1].split('(')[0].strip()
	                    print(uid)
	                    info_response = newinfo(uid)
	                    print(uid)
	                    uid = uid + 'َKKKKKKKKKKKKK'
	                    infoo = info_response['info']
	                    print(infoo)
	                    basic_info = infoo['basic_info']
	                    clan_info = infoo['clan_info']
	                    clan_admin = infoo['clan_admin']
	                    print(clan_info)
	                    if clan_info == "false":
	                    	clan_info = "\nPlayer Not In Clan\n"
	                    else:
	                    	clan_id = clan_info['clanid']
	                    	clan_name = clan_info['clanname']
	                    	clan_level = clan_info['guildlevel']
	                    	clan_members = clan_info['livemember']
	                    	clan_admin_name = clan_admin['adminname']
	                    	clan_admin_brrank = clan_admin['brpoint']
	                    	clan_admin_exp = clan_admin['exp']
	                    	clan_admin_id = fix_num(clan_admin['idadmin'])
	                    	clan_admin_level = clan_admin['level']
	                    	clan_info = (	                        f" Clan Info :\n"
	                    	f"Clan ID : {fix_num(clan_id)}\n"
	                         f"Clan Name :  {clan_name}\n"
	                        f"Clan Level: {clan_level}\n\n"
	                        "Clan Admin Info : \n"
	                        f"ID : {clan_admin_id}\n"
	                        f"Name : {clan_admin_name}\n"
	                        f"Exp : {clan_admin_exp}\n"
	                        f"Level : {clan_admin_level}\n"
	                        f"Ranked (Br) Score : {clan_admin_brrank}\n"
	                        )
	                    
	                    if info_response['status'] == "ok":
		                    level = basic_info['level']
		                    likes = basic_info['likes']
		                    name = basic_info['username']
		                    region = basic_info['region']
		                    bio = basic_info['bio']
		                    if "|" in bio:
		                    	bio = bio.replace("|"," ")
		                    br_rank = fix_num(basic_info['brrankscore'])
		                    exp = fix_num(basic_info['Exp'])
		                    print(level,likes,name,region)
		                    message_info = (	                    
	                        f"[C][FFB300] Basic Account info :\n"
	                        f"Server : {region}\n"
	                        f"Name : {name}\n"
	                        f"Bio : {bio}\n"
	                        f"Level : {level}\n"
	                        f"Exp : {exp}\n"
	                        
	                        f"Likes : {fix_num(likes)}\n"
	                        f"Ranked (Br) Score : {br_rank}"
	                        

   f"{clan_info}\n"
   f"[FF0000]Command Sent By : {sender_name}\n"
   f"Command Sender Id : {fix_num(sender_id)}\n\n"
   
	                        

	                        )
	                    else:
	                    	message_info = (f"[C][B] [FF0000]-----------------------------------\n"
	                        f" Wrong ID ..\n"
	                         f" Please Check Again\n"
	                        
	                        f" DEV @wlx_demon\n"
	                        f"-----------------------------------")
	                    
	                    json_result = get_available_room(data.hex()[10:])
	                    parsed_data = json.loads(json_result)
	                    uid = parsed_data["5"]["data"]["1"]["data"]
	                    clients.send(
	                    self.GenResponsMsg(
	                        f"{generate_random_color()}Okay Sir, Please Wait..", uid
	                    )
	                )
#	                time.sleep(2)
#	                    time.sleep(2)
	                    json_result = get_available_room(data.hex()[10:])
	                    parsed_data = json.loads(json_result)
	                    uid = parsed_data["5"]["data"]["1"]["data"]
	                    print(message_info)
	                    clients.send(self.GenResponsMsg(message_info, uid))
	                    
	                    
	                    
	            if "1200" in data.hex()[0:4] and b"/likes" in data:
	                   
	                    json_result = get_available_room(data.hex()[10:])
	                    parsed_data = json.loads(json_result)
	                    uid = parsed_data["5"]["data"]["1"]["data"]
	                    clients.send(
	                    self.GenResponsMsg(
	                        f"{generate_random_color()}Okay Sir, Please Wait..", uid
	                    )
	                )
	                    command_split = re.split("/likes", str(data))
	                    player_id = command_split[1].split('(')[0].strip()
	                    print(player_id)
	                    likes_response = send_likes(player_id)
	                    status = likes_response['status']
	                    message = likes_response['message']
	                    print(message)
	                    json_result = get_available_room(data.hex()[10:])
	                    parsed_data = json.loads(json_result)
	                    uid = parsed_data["5"]["data"]["1"]["data"]
	                    clients.send(self.GenResponsMsg(message, uid))
	            	
	            	
	            	
	            	
	            if "1200" in data.hex()[0:4] and b"/check" in data:
	                
	                command_split = re.split("/check", str(data))
	                json_result = get_available_room(data.hex()[10:])
	                parsed_data = json.loads(json_result)
	                uid = parsed_data["5"]["data"]["1"]["data"]
	                clients.send(
	                self.GenResponsMsg(
	                        f"{generate_random_color()}Okay Sir, Please Wait..", uid
	                    )
	                )
	                if len(command_split) > 1:
	                    player_id = command_split[1].split("\\x")[0].strip()
	                    player_id = command_split[1].split('(')[0].strip()
	                    print(player_id)
	                    
	                    banned_status = check_banned_status(player_id)
	                    print(banned_status)
	                    player_id = fix_num(player_id)
	                    status = banned_status['status']
	                    print(status)
	                    json_result = get_available_room(data.hex()[10:])
	                    parsed_data = json.loads(json_result)
	                    uid = parsed_data["5"]["data"]["1"]["data"]
	                    response_message = (
	                       f"{generate_random_color()}Player Name: {banned_status['player_name']}\n"
	                        f"Player ID : {player_id}\n"
	                        f"Status: {status}"
	                    )
	                    print(response_message)
	                    clients.send(self.GenResponsMsg(response_message, uid))
	            if "1200" in data.hex()[0:4] and b"/help" in data:
	                
	                lines = "_"*2
	                
	                json_result = get_available_room(data.hex()[10:])
	                parsed_data = json.loads(json_result)
	                user_name = parsed_data['5']['data']['9']['data']['1']['data']
	                uid = parsed_data["5"]["data"]["1"]["data"]
	                if "***" in str(uid):
	                	uid = rrrrrrrrrrrrrr(uid)
	                
	                print(f"\nUser With ID : {uid}\nName : {user_name}\nStarted Help\n")
                	time = get_time(uid)
                	if time['status'] == "bad":
                		remove_user(uid)
                	elif time["status"] == "ok":
	                	clients.send(
	                    self.GenResponsMsg(
	                        f"""[B][C][FFFFFF] Contect @wlx_demon For VIP""", uid
	                    )
	                )            
	                clients.send(
	                    self.GenResponsMsg(
	                        f"""[B][C][FFFFFF]@wlx_demon""", uid
	                    )
	                )
	                clients.send(
		                    self.GenResponsMsg(
		                        f"""
	[B][C][FFFFFF]Hey {user_name} \nWELCOME TO ＦＦＷＬＸＤㅤᴮᴼᵀ
 
 [b][c][FFFFFF] Commands!!
 [c][b][FFFFFF] /5s [b][c][00ff00] Create 5 Players Group
 [b][c][FFFFFF] /6s [b][c][00ff00] Create 6 Players Group
 [b][c][FFFFFF] /room <uid> [b][c][00ff00] Room Spam
 [b][c][FFFFFF] /likes <uid>  [b][c][00ff00] Get Likes
 [b][c][FFFFFF] /info <uid>  [b][c][00ff00] Get Player Info
 [b][c][FFFFFF] /spam <uid> [b][c][00ff00] Spam Requests
 [b][c][FFFFFF] /admin [b][c][00ff00] For More Details
 [b][c][FFFFFF] /ai <text> [b][c][00ff00] For In Game Ai
 [b][c][FFFFFF] /fs  [b][c][00ff00] For Start


 [b][c][00ff00]Telegram @wlx_demon
	""", uid
		                    )
		                )

	            
		                

	            if "1200" in data.hex()[0:4] and b"/ai" in data:
	                i = re.split("/ai", str(data))[1]
	                if "***" in i:
	                    i = i.replace("***", "106")
	                sid = str(i).split("(\\x")[0].strip()
	                headers = {"Content-Type": "application/json"}
	                payload = {
	                    "contents": [
	                        {
	                            "parts": [
	                                {"text": sid}
	                            ]
	                        }
	                    ]
	                }
	                response = requests.post(
	                    f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=AIzaSyDZvi8G_tnMUx7loUu51XYBt3t9eAQQLYo",
	                    headers=headers,
	                    json=payload,
	                )
	                if response.status_code == 200:
	                    ai_data = response.json()
	                    ai_response = ai_data['candidates'][0]['content']['parts'][0]['text']
	                    json_result = get_available_room(data.hex()[10:])
	                    parsed_data = json.loads(json_result)
	                    uid = parsed_data["5"]["data"]["1"]["data"]
	                    clients.send(
	                        self.GenResponsMsg(
	                            ai_response, uid
	                        )
	                    )
	                else:
	                    print("Error with AI API:", response.status_code, response.text)
	                    
                    
    def parse_my_message(self, serialized_data):
        MajorLogRes = MajorLoginRes_pb2.MajorLoginRes()
        MajorLogRes.ParseFromString(serialized_data)
        
        timestamp = MajorLogRes.kts
        key = MajorLogRes.ak
        iv = MajorLogRes.aiv
        BASE64_TOKEN = MajorLogRes.token
        timestamp_obj = Timestamp()
        timestamp_obj.FromNanoseconds(timestamp)
        timestamp_seconds = timestamp_obj.seconds
        timestamp_nanos = timestamp_obj.nanos
        combined_timestamp = timestamp_seconds * 1_000_000_000 + timestamp_nanos
        return combined_timestamp, key, iv, BASE64_TOKEN

    def GET_PAYLOAD_BY_DATA(self,JWT_TOKEN , NEW_ACCESS_TOKEN,date):
        token_payload_base64 = JWT_TOKEN.split('.')[1]
        token_payload_base64 += '=' * ((4 - len(token_payload_base64) % 4) % 4)
        decoded_payload = base64.urlsafe_b64decode(token_payload_base64).decode('utf-8')
        decoded_payload = json.loads(decoded_payload)
        NEW_EXTERNAL_ID = decoded_payload['external_id']
        SIGNATURE_MD5 = decoded_payload['signature_md5']
        now = datetime.now()
        now =str(now)[:len(str(now))-7]
        formatted_time = date
        payload = bytes.fromhex("1a13323032352d30322d32362031343a30333a3237220966726565206669726528013a07312e3130392e334239416e64726f6964204f532039202f204150492d32382028504b51312e3138303930342e3030312f5631312e302e332e302e5045494d49584d294a0848616e6468656c64520d4d61726f632054656c65636f6d5a1243617272696572446174614e6574776f726b60dc0b68ee0572033333327a1d41524d3634204650204153494d4420414553207c2031383034207c203880019d1d8a010f416472656e6f2028544d29203530399201404f70656e474c20455320332e322056403333312e30202847495440636635376339632c204931636235633464316363292028446174653a30392f32332f3138299a012b476f6f676c657c34303663613862352d343633302d343062622d623535662d373834646264653262656365a2010d3130322e35322e3137362e3837aa0102656eb201206431616539613230633836633463303433666434616134373931313438616135ba010134c2010848616e6468656c64ca01135869616f6d69205265646d69204e6f74652035ea014030363538396138383431623331323064363962333138373737653939366236313838336631653162323463383263616365303439326231653761313631656133f00101ca020d4d61726f632054656c65636f6dd202023447ca03203734323862323533646566633136343031386336303461316562626665626466e003bd9203e803d772f003a017f803468004e7738804bd92039004e7739804bd9203c80401d2043f2f646174612f6170702f636f6d2e6474732e667265656669726574682d51614b46585768325f61717257642d434d58554d33673d3d2f6c69622f61726d3634e00401ea045f35623839326161616264363838653537316636383830353331313861313632627c2f646174612f6170702f636f6d2e6474732e667265656669726574682d51614b46585768325f61717257642d434d58554d33673d3d2f626173652e61706bf00403f804028a050236349a050a32303139313138303734a80503b205094f70656e474c455332b805ff7fc00504ca05094750174f05550b5135d20506416761646972da05023039e0059239ea0507616e64726f6964f2055c4b717348543376464d434e5a7a4f4966476c5a52584e657a3765646b576b5354546d6a446b6a3857313556676d44526c3257567a477a324f77342f42726259412f5a5a304e302b59416f4651477a5950744e6f51384835335534513df805fbe4068806019006019a060134a2060134")
        payload = payload.replace(b"2024-12-26 13:02:43", str(now).encode())
        payload = payload.replace(b"88332848f415ca9ca98312edcd5fe8bc6547bc6d0477010a7feaf97e3435aa7f", NEW_ACCESS_TOKEN.encode("UTF-8"))
        payload = payload.replace(b"e1ccc10e70d823f950f9f4c337d7d20a", NEW_EXTERNAL_ID.encode("UTF-8"))
        payload = payload.replace(b"7428b253defc164018c604a1ebbfebdf", SIGNATURE_MD5.encode("UTF-8"))
        PAYLOAD = payload.hex()
        PAYLOAD = encrypt_api(PAYLOAD)
        PAYLOAD = bytes.fromhex(PAYLOAD)
        ip,port = self.GET_LOGIN_DATA(JWT_TOKEN , PAYLOAD)
        return ip,port
    
    def dec_to_hex(ask):
        ask_result = hex(ask)
        final_result = str(ask_result)[2:]
        if len(final_result) == 1:
            final_result = "0" + final_result
            return final_result
        else:
            return final_result
    def convert_to_hex(PAYLOAD):
        hex_payload = ''.join([f'{byte:02x}' for byte in PAYLOAD])
        return hex_payload
    def convert_to_bytes(PAYLOAD):
        payload = bytes.fromhex(PAYLOAD)
        return payload
    def GET_LOGIN_DATA(self, JWT_TOKEN, PAYLOAD):
        url = "https://client.ind.freefiremobile.com/GetLoginData"
        headers = {
            'Expect': '100-continue',
            'Authorization': f'Bearer {JWT_TOKEN}',
            'X-Unity-Version': '2018.4.11f1',
            'X-GA': 'v1 1',
            'ReleaseVersion': 'OB49',
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; G011A Build/PI)',
            'Host': 'clientbp.common.ggbluefox.com',
            'Connection': 'close',
            'Accept-Encoding': 'gzip, deflate, br',
        }
        
        max_retries = 3
        attempt = 0

        while attempt < max_retries:
            try:
                response = requests.post(url, headers=headers, data=PAYLOAD,verify=False)
                response.raise_for_status()
                x = response.content.hex()
                json_result = get_available_room(x)
                parsed_data = json.loads(json_result)
                print(parsed_data)
                address = parsed_data['32']['data']
                ip = address[:len(address) - 6]
                port = address[len(address) - 5:]
                return ip, port
            
            except requests.RequestException as e:
                print(f"Request failed: {e}. Attempt {attempt + 1} of {max_retries}. Retrying...")
                attempt += 1
                time.sleep(2)

        print("Failed to get login data after multiple attempts.")
        return None, None

    def guest_token(self,uid , password):
        url = "https://100067.connect.garena.com/oauth/guest/token/grant"
        headers = {"Host": "100067.connect.garena.com","User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)","Content-Type": "application/x-www-form-urlencoded","Accept-Encoding": "gzip, deflate, br","Connection": "close",}
        data = {"uid": f"{uid}","password": f"{password}","response_type": "token","client_type": "2","client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3","client_id": "100067",}
        response = requests.post(url, headers=headers, data=data)
        data = response.json()
        NEW_ACCESS_TOKEN = data['access_token']
        NEW_OPEN_ID = data['open_id']
        OLD_ACCESS_TOKEN = "06589a8841b3120d69b318777e996b61883f1e1b24c82cace0492b1e7a161ea3"
        OLD_OPEN_ID = "d1ae9a20c86c4c043fd4aa4791148aa5"
        time.sleep(0.2)
        data = self.TOKEN_MAKER(OLD_ACCESS_TOKEN , NEW_ACCESS_TOKEN , OLD_OPEN_ID , NEW_OPEN_ID,uid)
        return(data)
        
    def TOKEN_MAKER(self,OLD_ACCESS_TOKEN , NEW_ACCESS_TOKEN , OLD_OPEN_ID , NEW_OPEN_ID,id):
        headers = {
            'X-Unity-Version': '2018.4.11f1',
            'ReleaseVersion': 'OB49',
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-GA': 'v1 1',
            'Content-Length': '928',
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)',
            'Host': 'loginbp.common.ggbluefox.com',
            'Connection': 'Keep-Alive',
            'Accept-Encoding': 'gzip'
        }
        data = bytes.fromhex('1a13323032352d30322d32362031343a30333a3237220966726565206669726528013a07312e3130392e334239416e64726f6964204f532039202f204150492d32382028504b51312e3138303930342e3030312f5631312e302e332e302e5045494d49584d294a0848616e6468656c64520d4d61726f632054656c65636f6d5a1243617272696572446174614e6574776f726b60dc0b68ee0572033333327a1d41524d3634204650204153494d4420414553207c2031383034207c203880019d1d8a010f416472656e6f2028544d29203530399201404f70656e474c20455320332e322056403333312e30202847495440636635376339632c204931636235633464316363292028446174653a30392f32332f3138299a012b476f6f676c657c34303663613862352d343633302d343062622d623535662d373834646264653262656365a2010d3130322e35322e3137362e3837aa0102656eb201206431616539613230633836633463303433666434616134373931313438616135ba010134c2010848616e6468656c64ca01135869616f6d69205265646d69204e6f74652035ea014030363538396138383431623331323064363962333138373737653939366236313838336631653162323463383263616365303439326231653761313631656133f00101ca020d4d61726f632054656c65636f6dd202023447ca03203734323862323533646566633136343031386336303461316562626665626466e003bd9203e803d772f003a017f803468004e7738804bd92039004e7739804bd9203c80401d2043f2f646174612f6170702f636f6d2e6474732e667265656669726574682d51614b46585768325f61717257642d434d58554d33673d3d2f6c69622f61726d3634e00401ea045f35623839326161616264363838653537316636383830353331313861313632627c2f646174612f6170702f636f6d2e6474732e667265656669726574682d51614b46585768325f61717257642d434d58554d33673d3d2f626173652e61706bf00403f804028a050236349a050a32303139313138303734a80503b205094f70656e474c455332b805ff7fc00504ca05094750174f05550b5135d20506416761646972da05023039e0059239ea0507616e64726f6964f2055c4b717348543376464d434e5a7a4f4966476c5a52584e657a3765646b576b5354546d6a446b6a3857313556676d44526c3257567a477a324f77342f42726259412f5a5a304e302b59416f4651477a5950744e6f51384835335534513df805fbe4068806019006019a060134a2060134')
        data = data.replace(OLD_OPEN_ID.encode(),NEW_OPEN_ID.encode())
        data = data.replace(OLD_ACCESS_TOKEN.encode() , NEW_ACCESS_TOKEN.encode())
        hex = data.hex()
        d = encrypt_api(data.hex())
        Final_Payload = bytes.fromhex(d)
        URL = "https://loginbp.ggblueshark.com/MajorLogin"

        RESPONSE = requests.post(URL, headers=headers, data=Final_Payload,verify=False)
        
        combined_timestamp, key, iv, BASE64_TOKEN = self.parse_my_message(RESPONSE.content)
        if RESPONSE.status_code == 200:
            if len(RESPONSE.text) < 10:
                return False
            ip,port =self.GET_PAYLOAD_BY_DATA(BASE64_TOKEN,NEW_ACCESS_TOKEN,1)
            self.key = key
            self.iv = iv
            print(key, iv)
            return(BASE64_TOKEN,key,iv,combined_timestamp,ip,port)
        else:
            return False
    
    def time_to_seconds(hours, minutes, seconds):
        return (hours * 3600) + (minutes * 60) + seconds

    def seconds_to_hex(seconds):
        return format(seconds, '04x')
    
    def extract_time_from_timestamp(timestamp):
        dt = datetime.fromtimestamp(timestamp)
        h = dt.hour
        m = dt.minute
        s = dt.second
        return h, m, s
    
    def get_tok(self):
        global g_token
        token, key, iv, Timestamp, ip, port = self.guest_token(self.id, self.password)
        g_token = token
        print(ip, port)
        try:
            decoded = jwt.decode(token, options={"verify_signature": False})
            account_id = decoded.get('account_id')
            encoded_acc = hex(account_id)[2:]
            hex_value = dec_to_hex(Timestamp)
            time_hex = hex_value
            BASE64_TOKEN_ = token.encode().hex()
            print(f"Token decoded and processed. Account ID: {account_id}")
        except Exception as e:
            print(f"Error processing token: {e}")
            return

        try:
            head = hex(len(encrypt_packet(BASE64_TOKEN_, key, iv)) // 2)[2:]
            length = len(encoded_acc)
            zeros = '00000000'

            if length == 9:
                zeros = '0000000'
            elif length == 8:
                zeros = '00000000'
            elif length == 10:
                zeros = '000000'
            elif length == 7:
                zeros = '000000000'
            else:
                print('Unexpected length encountered')
            head = f'0115{zeros}{encoded_acc}{time_hex}00000{head}'
            final_token = head + encrypt_packet(BASE64_TOKEN_, key, iv)
            print("Final token constructed successfully.")
        except Exception as e:
            print(f"Error constructing final token: {e}")
        token = final_token
        self.connect(token, ip, port, 'anything', key, iv)
        
      
        return token, key, iv
        
ids_passwords = []

with open("accs.txt", "r") as file:
    for line in file:
        if line.strip():  # skip empty lines
            try:
                entry = json.loads(line)
                uid = entry["guest_account_info"]["com.garena.msdk.guest_uid"]
                password = entry["guest_account_info"]["com.garena.msdk.guest_password"]
                ids_passwords.append((uid, password))
            except (json.JSONDecodeError, KeyError) as e:
                print(f"Skipping line due to error: {e}")

def run_client(id, password):
    print(f"ID: {id}, Password: {password}")
    client = FF_CLIENT(id, password)
    client.start()
    
max_range = 300000
num_clients = len(ids_passwords)
num_threads = 1
start = 0
end = max_range
step = (end - start) // num_threads
threads = []
for i in range(num_threads):
    ids_for_thread = ids_passwords[i % num_clients]
    id, password = ids_for_thread
    thread = threading.Thread(target=run_client, args=(id, password))
    threads.append(thread)
    time.sleep(3)
    thread.start()

for thread in threads:
    thread.join()
    
if __name__ == "__main__":
    try:
        client_thread = FF_CLIENT(id="4152983703", password="EE71E3CBEE683CED325EE25FC075E61B8A7BA793EE525AC25FC1573F8A60F3C0")
        client_thread.start()
    except Exception as e:
        logging.error(f"Error occurred: {e}")
        restart_program()
