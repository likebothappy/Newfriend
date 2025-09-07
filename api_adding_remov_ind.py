import httpx
import time
import re
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import json
import threading
from concurrent.futures import ThreadPoolExecutor
import concurrent.futures
from flask import Flask, request, jsonify, abort, render_template_string
from datetime import datetime
from datetime import datetime, timedelta
import threading
from threading import Thread
from flask import Flask, jsonify, request
import asyncio
from protobuf_decoder.protobuf_decoder import Parser
import binascii
####################################
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder
####################################
app = Flask(__name__)
###########FREE-FIRE-VERSION###########
freefire_version = "ob50"
apis_code = "Fox-7CdxP"
apis_code_2 = "projects_xxx_3ei93k_codex_xdfox"
#############KEY-AES-CBC#############
key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
############ENCRYPT-UID##############
def Encrypt_ID(x):
    x = int(x)
    dec = [ '80', '81', '82', '83', '84', '85', '86', '87', '88', '89', '8a', '8b', '8c', '8d', '8e', '8f', '90', '91', '92', '93', '94', '95', '96', '97', '98', '99', '9a', '9b', '9c', '9d', '9e', '9f', 'a0', 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7', 'a8', 'a9', 'aa', 'ab', 'ac', 'ad', 'ae', 'af', 'b0', 'b1', 'b2', 'b3', 'b4', 'b5', 'b6', 'b7', 'b8', 'b9', 'ba', 'bb', 'bc', 'bd', 'be', 'bf', 'c0', 'c1', 'c2', 'c3', 'c4', 'c5', 'c6', 'c7', 'c8', 'c9', 'ca', 'cb', 'cc', 'cd', 'ce', 'cf', 'd0', 'd1', 'd2', 'd3', 'd4', 'd5', 'd6', 'd7', 'd8', 'd9', 'da', 'db', 'dc', 'dd', 'de', 'df', 'e0', 'e1', 'e2', 'e3', 'e4', 'e5', 'e6', 'e7', 'e8', 'e9', 'ea', 'eb', 'ec', 'ed', 'ee', 'ef', 'f0', 'f1', 'f2', 'f3', 'f4', 'f5', 'f6', 'f7', 'f8', 'f9', 'fa', 'fb', 'fc', 'fd', 'fe', 'ff']
    xxx= [ '1','01', '02', '03', '04', '05', '06', '07', '08', '09', '0a', '0b', '0c', '0d', '0e', '0f', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '1a', '1b', '1c', '1d', '1e', '1f', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '2a', '2b', '2c', '2d', '2e', '2f', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '3a', '3b', '3c', '3d', '3e', '3f', '40', '41', '42', '43', '44', '45', '46', '47', '48', '49', '4a', '4b', '4c', '4d', '4e', '4f', '50', '51', '52', '53', '54', '55', '56', '57', '58', '59', '5a', '5b', '5c', '5d', '5e', '5f', '60', '61', '62', '63', '64', '65', '66', '67', '68', '69', '6a', '6b', '6c', '6d', '6e', '6f', '70', '71', 
    '72', '73', '74', '75', '76', '77', '78', '79', '7a', '7b', '7c', '7d', '7e', '7f']
    x= x/128 
    if x>128:
        x =x/128
        if x >128:
            x= x/128
            if x>128:
                x= x/128
                strx= int(x)
                y= (x-int(strx))*128
                stry =str(int(y))
                z = (y-int(stry))*128
                strz =str(int(z))
                n =(z-int(strz))*128
                strn=str(int(n))
                m=(n-int(strn))*128
                return dec[int(m)]+dec[int(n)]+dec[int(z)]+dec[int(y)]+xxx[int(x)]
            else:
                strx= int(x)
                y= (x-int(strx))*128
                stry =str(int(y))
                z = (y-int(stry))*128
                strz =str(int(z))
                n =(z-int(strz))*128
                strn=str(int(n))
                return dec[int(n)]+dec[int(z)]+dec[int(y)]+xxx[int(x)]
def encrypt_api(plain_text):
    plain_text = bytes.fromhex(plain_text)
    key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()
######ENCRYPT&DECRYPT-ID-EMOTES#######
def Encrypt_id_emote(uid):
    result = []
    while uid > 0:
        byte = uid & 0x7F
        uid >>= 7
        if uid > 0:
            byte |= 0x80
        result.append(byte)
    return bytes(result).hex()
def Decrypt_id_emote(uidd):
    bytes_value = bytes.fromhex(uidd)
    r, _ = 0, 0
    for byte in bytes_value:
        r |= (byte & 0x7F) << _
        if not (byte & 0x80):
            break
        _ += 7
    return r
############convert_timestamp##########
def convert_timestamp(release_time):
    return datetime.utcfromtimestamp(release_time).strftime('%Y-%m-%d %H:%M:%S')
##############generate_packet##########
def max_length(text):
    if len(text) > 420:
        text = text[:420]
    elif len(text) < 420:
        fill_length = 420 - len(text)
        text += "00" * ((fill_length + 1) // 2)
        text = text[:420]
    return text
def generate_packet(id, text):
    msg = text.encode('utf-8').hex()
    txt = max_length(msg)
    packet = f"120000018d08{id}101220022a800308{id}10{id}22d201{txt}28f0ed8db7064a3d0a18efbca2efbcb2efbcb3e385a4efbcadefbcafefbcb2efbcaf10dedd8dae031893b6d3ad0320d7012883f9f7b103420c47524f564553545249544348520261726a520a4c68747470733a2f2f67726170682e66616365626f6f6b2e636f6d2f76392e302f3132303434333431303231333534352f706963747572653f77696474683d313630266865696768743d313630100118017200"
    return packet
########PROTOBUF-INFO-CLAN###########
_sym_db = _symbol_database.Default()
DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(
    b'\n\ndata.proto\x12\x05proto\"\xa4\x05\n\x08response\x12\n\n\x02id\x18\x01 \x01(\r\x12\x14\n\x0cspecial_code\x18\x02 \x01(\t\x12\x12\n\ntimestamp1\x18\x03 \x01(\r\x12\x0f\n\x07value_a\x18\x04 \x01(\r\x12\x13\n\x0bstatus_code\x18\x05 \x01(\r\x12\x10\n\x08sub_type\x18\x06 \x01(\r\x12\x0f\n\x07version\x18\x07 \x01(\r\x12\r\n\x05level\x18\x08 \x01(\r\x12\r\n\x05\x66lags\x18\t \x01(\r\x12\x17\n\x0fwelcome_message\x18\x0c \x01(\t\x12\x0e\n\x06region\x18\r \x01(\t\x12\x15\n\rjson_metadata\x18\x0e \x01(\t\x12\x13\n\x0b\x62ig_numbers\x18\x0f \x01(\t\x12\x0f\n\x07\x62\x61lance\x18\x14 \x01(\r\x12\r\n\x05score\x18\x16 \x01(\r\x12\x10\n\x08upgrades\x18! \x01(\r\x12\x14\n\x0c\x61\x63hievements\x18# \x01(\r\x12\x16\n\x0etotal_playtime\x18$ \x01(\r\x12\x0e\n\x06\x65nergy\x18% \x01(\r\x12\x0c\n\x04rank\x18& \x01(\r\x12\n\n\x02xp\x18\' \x01(\r\x12\x12\n\ntimestamp2\x18( \x01(\r\x12\x12\n\nerror_code\x18) \x01(\r\x12\x13\n\x0blast_active\x18, \x01(\r\x12\x30\n\rguild_details\x18/ \x01(\x0b\x32\x19.proto.response.GuildInfo\x12\x13\n\x0b\x65mpty_field\x18\x31 \x01(\t\x1a\x97\x01\n\tGuildInfo\x12\x0e\n\x06region\x18\x01 \x01(\t\x12\x0f\n\x07\x63lan_id\x18\x02 \x01(\r\x12\x16\n\x0emembers_online\x18\x03 \x01(\r\x12\x15\n\rtotal_members\x18\x04 \x01(\r\x12\x10\n\x08regional\x18\x05 \x01(\r\x12\x13\n\x0breward_time\x18\x06 \x01(\r\x12\x13\n\x0b\x65xpire_time\x18\x07 \x01(\rb\x06proto3'
)
_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'data_pb2', _globals)
if _descriptor._USE_C_DESCRIPTORS == False:
    DESCRIPTOR._options = None
    _globals['_RESPONSE']._serialized_start = 14
    _globals['_RESPONSE']._serialized_end = 54
ResponseMessage = _sym_db.GetSymbol('proto.response')
_sym_db = _symbol_database.Default()
DESCRIPTOR2 = _descriptor_pool.Default().AddSerializedFile(b'\n\x14\x65ncode_id_clan.proto\"(\n\x06MyData\x12\x0e\n\x06\x66ield1\x18\x01 \x01(\r\x12\x0e\n\x06\x66ield2\x18\x02 \x01(\rb\x06proto3')
_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR2, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR2, 'encode_id_clan_pb2', _globals)
if _descriptor._USE_C_DESCRIPTORS == False:
  DESCRIPTOR2._options = None
  _globals['_MYDATA']._serialized_start=24
  _globals['_MYDATA']._serialized_end=64
MyData = _sym_db.GetSymbol('MyData')
########PROTOBUF-INFO-WISHLIST########
_sym_db = _symbol_database.Default()
DESCRIPTOR3 = _descriptor_pool.Default().AddSerializedFile(b'\n\x16GetWishListItems.proto\x12\x05proto\"+\n\x15\x43SGetWishListItemsReq\x12\x12\n\naccount_id\x18\x01 \x01(\x04\"5\n\x0cWishItemInfo\x12\x0f\n\x07item_id\x18\x01 \x01(\r\x12\x14\n\x0crelease_time\x18\x02 \x01(\x04\";\n\x15\x43SGetWishListItemsRes\x12\"\n\x05items\x18\x01 \x03(\x0b\x32\x13.proto.WishItemInfob\x06proto3')
_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR3, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR3, 'GetWishListItems_pb2', _globals)
if _descriptor._USE_C_DESCRIPTORS == False:
  DESCRIPTOR3._options = None
  _globals['_CSGETWISHLISTITEMSREQ']._serialized_start=33
  _globals['_CSGETWISHLISTITEMSREQ']._serialized_end=76
  _globals['_WISHITEMINFO']._serialized_start=78
  _globals['_WISHITEMINFO']._serialized_end=131
  _globals['_CSGETWISHLISTITEMSRES']._serialized_start=133
  _globals['_CSGETWISHLISTITEMSRES']._serialized_end=192
########PROTOBUF-LONG-BIO############
_sym_db = _symbol_database.Default()
DESCRIPTOR_long_bio = _descriptor_pool.Default().AddSerializedFile(b'\n\x14proto_long_bio.proto\"\xbb\x01\n\x04\x44\x61ta\x12\x0f\n\x07\x66ield_2\x18\x02 \x01(\x05\x12\x1e\n\x07\x66ield_5\x18\x05 \x01(\x0b\x32\r.EmptyMessage\x12\x1e\n\x07\x66ield_6\x18\x06 \x01(\x0b\x32\r.EmptyMessage\x12\x0f\n\x07\x66ield_8\x18\x08 \x01(\t\x12\x0f\n\x07\x66ield_9\x18\t \x01(\x05\x12\x1f\n\x08\x66ield_11\x18\x0b \x01(\x0b\x32\r.EmptyMessage\x12\x1f\n\x08\x66ield_12\x18\x0c \x01(\x0b\x32\r.EmptyMessage\"\x0e\n\x0c\x45mptyMessageb\x06proto3')
_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR_long_bio, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR_long_bio, 'proto_long_bio_pb2', _globals)
if _descriptor._USE_C_DESCRIPTORS == False:
  DESCRIPTOR_long_bio._options = None
  _globals['_DATA']._serialized_start=25
  _globals['_DATA']._serialized_end=202
  _globals['_EMPTYMESSAGE']._serialized_start=204
  _globals['_EMPTYMESSAGE']._serialized_end=218
Data = _sym_db.GetSymbol('Data')
EmptyMessage = _sym_db.GetSymbol('EmptyMessage')
#############GetJwtToken##############
jwt_token = None
async def get_jwt_token():
    global jwt_token
    url = "https://projects-fox-x-get-jwt.vercel.app/get?uid=3763606630&password=7FF33285F290DDB97D9A31010DCAA10C2021A03F27C4188A2F6ABA418426527C"
    while True:
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(url)
                if response.status_code == 200:
                    data = response.json()
                    if data['status'] == 'success':
                        jwt_token = data['token']
                        print("JWT Token updated successfully.")
                        print(f"Token: {jwt_token}")
                        return jwt_token
                    else:
                        print("Failed to get JWT token: Status is not success.")
                else:
                    print(f"Failed to get JWT token: HTTP {response.status_code}")
        except httpx.RequestError as e:
            print(f"Request error: {e}")
        await asyncio.sleep(5)
async def ensure_jwt_token():
    global jwt_token
    if not jwt_token:
        print("JWT token is missing. Attempting to fetch a new one...")
        try:
            await get_jwt_token()
        except Exception as e:
            print(f"Failed to ensure JWT token: {e}")
            raise
    return jwt_token
async def startup():
    await get_jwt_token()

@app.route('/')
def home():
    # HTML يحتوي على شرح APIs
    html_content = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CODEX TEAM APIs</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f4f4f9;
            color: #333;
            line-height: 1.6;
            padding: 20px;
        }
        .container {
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            background: #fff;
            border-radius: 8px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        h1 {
            text-align: center;
            margin-bottom: 20px;
            color: #444;
        }
        .api-list {
            display: flex;
            flex-direction: column;
            gap: 15px;
        }
        .api-item {
            background: #f9f9f9;
            padding: 15px;
            border-radius: 6px;
            border: 1px solid #ddd;
        }
        .api-item strong {
            display: block;
            margin-bottom: 5px;
            color: #555;
        }
        .api-item code {
            background: #eaeaea;
            padding: 3px 6px;
            border-radius: 4px;
            font-family: monospace;
            color: #333;
        }
        .footer {
            text-align: center;
            margin-top: 20px;
            font-size: 14px;
            color: #777;
        }
        .note {
            text-align: center;
            margin-bottom: 20px;
            color: #ff0000;
            font-weight: bold;
        }
        .panel {
            margin-top: 30px;
            padding: 20px;
            background: #e3f2fd;
            border-radius: 8px;
            border: 1px solid #90caf9;
        }
        .panel h2 {
            text-align: center;
            color: #1976d2;
            margin-bottom: 20px;
        }
        .new-apis {
            margin-top: 30px;
            padding: 20px;
            background: #fff3e0;
            border-radius: 8px;
            border: 1px solid #ffcc80;
        }
        .new-apis h2 {
            text-align: center;
            color: #ef6c00;
            margin-bottom: 20px;
        }
        .key-notice {
            text-align: center;
            padding: 15px;
            background: #ffebee;
            border-radius: 8px;
            border: 1px solid #ef9a9a;
            margin-bottom: 20px;
            font-weight: bold;
            color: #c62828;
        }
        .key-notice code {
            background: #ffcdd2;
            padding: 3px 6px;
            border-radius: 4px;
            font-family: monospace;
            color: #c62828;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="key-notice">
            <p><code>key1 = Fox-7CdxP</code></p>
            <p><code>key2 = this privat key for get Dm fox</code></p>
        </div>
        <h1>CODEX TEAM APIs</h1>
        <div class="note">
            These APIs only support ME Server!
        </div>
        <div class="api-list">
            <div class="api-item">
                <strong>Clan Information:</strong>
                <code>/get_clan_info?clan_id={clan_id}&key={key1}</code>
                <p>Get clan information using clan ID and API key.</p>
                <p>Example: <code>https://projects-fox-apis.vercel.app/get_clan_info?clan_id=12345&key=your_api_key</code></p>
            </div>
            <div class="api-item">
                <strong>Wishlist Information:</strong>
                <code>/wishlist?uid={uid}&key={key1}</code>
                <p>Get player's wishlist using player UID and API key.</p>
                <p>Example: <code>https://projects-fox-apis.vercel.app/wishlist?uid=12345678&key=your_api_key</code></p>
            </div>
            <div class="api-item">
                <strong>Fetch Events:</strong>
                <code>/eventes?key={key1}</code>
                <p>Fetch a list of available events using API key.</p>
                <p>Example: <code>https://projects-fox-apis.vercel.app/eventes?key=your_api_key</code></p>
            </div>
            <div class="api-item">
                <strong>Player Information:</strong>
                <code>/player_info?uid={uid}&key={key1}</code>
                <p>Get player information using player UID and API key.</p>
                <p>Example: <code>https://projects-fox-apis.vercel.app/player_info?uid=12345&key=your_api_key</code></p>
            </div>
            <div class="api-item">
                <strong>Check Account Status and Server:</strong>
                <code>/check?uid={uid}&key={key1}</code>
                <p>Check if an account is banned and its server using UID and API key.</p>
                <p>Example: <code>https://projects-fox-apis.vercel.app/check?uid=12345&key=your_api_key</code></p>
            </div>
        </div>

        <div class="panel">
            <h2>Bot Panel APIs</h2>
            <div class="api-list">
                <div class="api-item">
                    <strong>Delete Bot Code:</strong>
                    <code>/delete_code?code={bot_code}&key={key2}</code>
                    <p>Delete a bot code using the code and API key.</p>
                    <p>Example: <code>https://projects-fox-apis.vercel.app/delete_code?code=your_bot_code&key=key2</code></p>
                </div>
                <div class="api-item">
                    <strong>Get Bot Code:</strong>
                    <code>/get_code?key={key2}</code>
                    <p>Get a bot code using API key.</p>
                    <p>Example: <code>https://projects-fox-apis.vercel.app/get_code?key=key2</code></p>
                </div>
                <div class="api-item">
                    <strong>Create New Bot Code:</strong>
                    <code>/new_code?code={bot_code}&heurs={heurs}&key={key2}</code>
                    <p>Create a new bot code with expiration hours using the code, hours, and API key.</p>
                    <p>Example: <code>https://projects-fox-apis.vercel.app/new_code?code=your_bot_code&heurs=24&key=key2</code></p>
                </div>
            </div>
        </div>

        <div class="new-apis">
            <h2>New APIs</h2>
            <div class="api-list">
                <div class="api-item">
                    <strong>Visit Player:</strong>
                    <code>/visit?uid={uid}&key={key1}</code>
                    <p>Visit a player's profile using their UID and API key.</p>
                    <p>Example: <code>https://projects-fox-apis.vercel.app/visit?uid=12345&key=your_api_key</code></p>
                </div>
                <div class="api-item">
                    <strong>Decode Emote:</strong>
                    <code>/decode_emote?uid={uid}&key={key2}</code>
                    <p>Decode a player's emote using their UID and API key.</p>
                    <p>Example: <code>https://projects-fox-apis.vercel.app/decode_emote?uid=12345&key=key2</code></p>
                </div>
                <div class="api-item">
                    <strong>Encode Emote:</strong>
                    <code>/encode_emote?uid={uid}&key={key2}</code>
                    <p>Encode a player's emote using their UID and API key.</p>
                    <p>Example: <code>https://projects-fox-apis.vercel.app/encode_emote?uid=12345&key=key2</code></p>
                </div>
                <div class="api-item">
                    <strong>Add Friend:</strong>
                    <code>/adding_friend?token={jwt_token}&uid={uid}&key={key2}</code>
                    <p>Add a friend using JWT token, player UID, and API key.</p>
                    <p>Example: <code>https://projects-fox-apis.vercel.app/adding_friend?token=your_jwt_token&uid=12345&key=key2</code></p>
                </div>
                <div class="api-item">
                    <strong>Remove Friend:</strong>
                    <code>/remove_friend?token={jwt_token}&uid={uid}&key={key2}</code>
                    <p>Remove a friend using JWT token, player UID, and API key.</p>
                    <p>Example: <code>https://projects-fox-apis.vercel.app/remove_friend?token=your_jwt_token&uid=12345&key=key2</code></p>
                </div>
                <div class="api-item">
                    <strong>Set Long Bio:</strong>
                    <code>/long_bio?bio={bio}&token={jwt_token}&key={key1}</code>
                    <p>Set a long bio using bio text, JWT token, and API key.</p>
                    <p>Example: <code>https://projects-fox-apis.vercel.app/long_bio?bio=YourBioHere&token=your_jwt_token&key=key1</code></p>
                </div>
            </div>
        </div>

        <div class="footer">
            &copy; 2025 ProjectS FoxX!!
        </div>
    </div>
</body>
</html>
    """
    return render_template_string(html_content)
####################################
@app.route('/get_clan_info', methods=['GET'])
async def get_clan_info():
    global jwt_token
    try:
        await ensure_jwt_token()
    except Exception as e:
        return jsonify({"error": f"Failed to get JWT token: {str(e)}"}), 500
    clan_id = request.args.get('clan_id')
    code = request.args.get("key")
    if not clan_id or not code:
        return jsonify({"error": "Missing clan id or key"}), 400
    if code != apis_code:
        return jsonify({"error": "- Bad / Error Key !"}), 400
    json_data = '''
    {{
        "1": {},
        "2": 1
    }}
    '''.format(clan_id)
    data_dict = json.loads(json_data)
    my_data = MyData()
    my_data.field1 = data_dict["1"]
    my_data.field2 = data_dict["2"]
    print(clan_id)
    data_bytes = my_data.SerializeToString()
    padded_data = pad(data_bytes, AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_data = cipher.encrypt(padded_data)
    formatted_encrypted_data = ' '.join([f"{byte:02X}" for byte in encrypted_data])
    url = "https://clientbp.ggblueshark.com/GetClanInfoByClanID"
    data_hex = formatted_encrypted_data
    data_bytes = bytes.fromhex(data_hex.replace(" ", ""))
    headers = {
        "Expect": "100-continue",
        "Authorization": f"Bearer {jwt_token}",
        "X-Unity-Version": "2018.4.11f1",
        "X-GA": "v1 1",
        "ReleaseVersion": freefire_version,
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11; SM-A305F Build/RP1A.200720.012)",
        "Host": "clientbp.ggblueshark.com",
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip"
    }
    async with httpx.AsyncClient(timeout=60.0) as client:
        response = await client.post(url, headers=headers, data=data_bytes)
    if response.status_code == 200:
        if response.content:
            response_message = ResponseMessage()
            response_message.ParseFromString(response.content)
            timestamp1_normal = datetime.fromtimestamp(response_message.timestamp1)
            timestamp2_normal = datetime.fromtimestamp(response_message.timestamp2)
            last_active_normal = datetime.fromtimestamp(response_message.last_active)
            return jsonify({
                "id": response_message.id,
                "clan_name": response_message.special_code,
                "timestamp1": timestamp1_normal.strftime("%Y-%m-%d %H:%M:%S"),
                "value_a": response_message.value_a,
                "status_code": response_message.status_code,
                "sub_type": response_message.sub_type,
                "version": response_message.version,
                "level": response_message.level,
                "flags": response_message.flags,
                "welcome_message": response_message.welcome_message,
                "region": response_message.region,
                "json_metadata": response_message.json_metadata,
                "big_numbers": response_message.big_numbers,
                "balance": response_message.balance,
                "score": response_message.score,
                "upgrades": response_message.upgrades,
                "achievements": response_message.achievements,
                "total_playtime": response_message.total_playtime,
                "energy": response_message.energy,
                "rank": response_message.rank,
                "xp": response_message.xp,
                "timestamp2": timestamp2_normal.strftime("%Y-%m-%d %H:%M:%S"),
                "error_code": response_message.error_code,
                "last_active": last_active_normal.strftime("%Y-%m-%d %H:%M:%S"),
                "guild_details": {
                    "region": response_message.guild_details.region,
                    "clan_id": response_message.guild_details.clan_id,
                    "members_online": response_message.guild_details.members_online,
                    "total_members": response_message.guild_details.total_members,
                    "regional": response_message.guild_details.regional,
                    "reward_time": response_message.guild_details.reward_time,
                    "expire_time": response_message.guild_details.expire_time
                }
            })
        else:
            return jsonify({"error": "No content in response"}), 500
    else:
        return jsonify({"error": f"Failed to fetch data: {response.status_code}"}), response.status_code
############wishlist##################
@app.route('/wishlist', methods=['GET'])
async def get_wishlist():
    global jwt_token
    try:
        await ensure_jwt_token()
    except Exception as e:
        return jsonify({"error": f"Failed to get JWT token: {str(e)}"}), 500
    uid = request.args.get("uid")
    code = request.args.get("key")
    if not uid or not code:
        return jsonify({" error": "Missing uid or key"})
    if code != apis_code:
        return jsonify({"error": "- Bad / Error Key !"}), 400
    encrypted_id = Encrypt_ID(uid)
    encrypted_api = encrypt_api(f"08{encrypted_id}1007")
    TARGET = bytes.fromhex(encrypted_api)    
    url = "https://clientbp.ggblueshark.com/GetWishListItems"
    headers = {
        "Authorization": f"Bearer {jwt_token}",
        "X-Unity-Version": "2018.4.11f1",
        "X-GA": "v1 1",
        "ReleaseVersion": freefire_version,
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; SM-N975F Build/PI)",
        "Host": "clientbp.common.ggbluefox.com",
        "Connection": "close",
        "Accept-Encoding": "gzip, deflate, br",
    }    
    async with httpx.AsyncClient(timeout=60.0) as client:
        response = await client.post(url, headers=headers, data=TARGET)
        decoded_response = CSGetWishListItemsRes()
        decoded_response.ParseFromString(response.content)    
        wishlist = [
            {"item_id": item.item_id, "release_time": convert_timestamp(item.release_time)}
            for item in decoded_response.items
        ]    
        return jsonify({"uid": uid, "wishlist": wishlist})
#############API-VISIT################
async def get_player_information(player_id):
    global jwt_token
    try:
        await ensure_jwt_token()
    except Exception as e:
        return jsonify({"error": f"Failed to get JWT token: {str(e)}"}), 500
    encrypted_id = Encrypt_ID(player_id)
    encrypted_api = encrypt_api(f"08{encrypted_id}1007")
    target = bytes.fromhex(encrypted_api)
    url = "https://clientbp.common.ggbluefox.com/GetPlayerPersonalShow"
    headers = {
        "Authorization": f"Bearer {jwt_token}",
        "X-Unity-Version": "2018.4.11f1",
        "X-GA": "v1 1",
        "ReleaseVersion": freefire_version,
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; SM-N975F Build/PI)",
        "Host": "clientbp.common.ggbluefox.com",
        "Connection": "close",
        "Accept-Encoding": "gzip, deflate, br",
    }
    try:
        async with httpx.AsyncClient(timeout=30.0, verify=False) as client:
            response = await client.post(url, headers=headers, data=target)
            if response.status_code == 200:
                return f"Success for player {player_id}"
            else:
                return f"Failed for player {player_id}: HTTP {response.status_code}"
    except httpx.RequestError as e:
        return f"Request error for player {player_id}: {e}"

@app.route('/visit', methods=['GET'])
async def start_requests():
    uid = request.args.get('uid')
    code = request.args.get("key")
    if not uid or not code:
        return jsonify({" error": "Missing uid or key"}), 400
    if code != apis_code:
        return jsonify({"error": "- Bad / Error Key !"}), 400
    player_ids = [int(uid)] * 1
    tasks = [get_player_information(player_id) for player_id in player_ids]
    results = await asyncio.gather(*tasks)

    return jsonify({
        "TEAM": "By codex team",
        "DEV": "WELCOME TO ProjectS FoxX!!",
        "status": "success",
        "message": "1 requests sent successfully",
        "results": results
    })
###########API-ADDING-UID#############
@app.route('/adding_friend', methods=['GET'])
def adding_friend():
    token = request.args.get('token')
    target_id = request.args.get('id')
    code = request.args.get("key")
    if not id or not code:
        return jsonify({" error": "Missing uid or key"}), 400
    if code != apis_code_2:
        return jsonify({"error": "- Bad / Error Key !"}), 400
    if not token or not target_id:
        return jsonify({"error": "Token and ID are required"}), 400
    url = "https://client.ind.freefiremobile.com/RequestAddingFriend"
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "X-GA": "v1 1",
        "ReleaseVersion": freefire_version,
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8",
        "User-Agent": "Free%20Fire/2019117061 CFNetwork/1399 Darwin/22.1.0",
        "Connection": "keep-alive",
        "Authorization": f"Bearer {token}",
        "X-Unity-Version": "2018.4.11f1",
        "Accept": "/"
    }
    id_encrypted = Encrypt_ID(target_id)
    data0 = "08c8b5cfea1810" + id_encrypted + "18012008"
    data = bytes.fromhex(encrypt_api(data0))
    response = requests.post(url, headers=headers, data=data, verify=False)
    if response.status_code == 200:
        return jsonify({"message": "RequestaddFriend GOOD!"}), 200
    else:
        return jsonify({"error": f"Friend request not sent successfully {response.text}"}), 500
##########API-DELETING-UID#############
@app.route('/remove_friend', methods=['GET'])
def remove_friend():
    token = request.args.get('token')
    target_id = request.args.get('id')
    code = request.args.get("key")
    if not id or not code:
        return jsonify({" error": "Missing uid or key"}), 400
    if code != apis_code_2:
        return jsonify({"error": "- Bad / Error Key !"}), 400
    if not token or not target_id:
        return jsonify({"error": "Token and ID are required"}), 400
    url = "https://client.ind.freefiremobile.com/RemoveFriend"
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "X-GA": "v1 1",
        "ReleaseVersion": freefire_version,
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8",
        "User-Agent": "Free%20Fire/2019117061 CFNetwork/1399 Darwin/22.1.0",
        "Connection": "keep-alive",
        "Authorization": f"Bearer {token}",
        "X-Unity-Version": "2018.4.11f1",
        "Accept": "/"
    }
    id_encrypted = Encrypt_ID(target_id)
    data0 = "08c8b5cfea1810" + id_encrypted + "18012008"
    data = bytes.fromhex(encrypt_api(data0))
    response = requests.post(url, headers=headers, data=data, verify=False)
    if response.status_code == 200:
        return jsonify({"message": "RequestRemoveFriend GOOD!"}), 200
    else:
        return jsonify({"error": "HMMM ERROR BROO FUCK!!!"}), 500
###########API-LONG-BIO###############
@app.route("/long_bio", methods=['GET'])
def encrypt_data():
    bio = request.args.get('bio')
    token = request.args.get('token')
    code = request.args.get("key")
    if not token or not code or not bio:
        return jsonify({" error": "Missing bio or token or key"}), 400
    if code != apis_code:
        return jsonify({"error": "- Bad / Error Key !"}), 400
    if len(bio) >= 180:
        return jsonify({"error": "Bio must be less than 180 characters"}), 400
    key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    data = Data()
    data.field_2 = 17
    data.field_5.CopyFrom(EmptyMessage())
    data.field_6.CopyFrom(EmptyMessage())
    data.field_8 = bio
    data.field_9 = 1
    data.field_11.CopyFrom(EmptyMessage())
    data.field_12.CopyFrom(EmptyMessage())
    data_bytes = data.SerializeToString()
    padded_data = pad(data_bytes, AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_data = cipher.encrypt(padded_data)
    formatted_encrypted_data = ' '.join([f"{byte:02X}" for byte in encrypted_data])
    url = "https://clientbp.ggblueshark.com/UpdateSocialBasicInfo"
    data_hex = formatted_encrypted_data
    data_bytes = bytes.fromhex(data_hex.replace(" ", ""))
    headers = {
        "Expect": "100-continue",
        "Authorization": f"Bearer {token}",
        "X-Unity-Version": "2018.4.11f1",
        "X-GA": "v1 1",
        "ReleaseVersion": freefire_version,
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11; SM-A305F Build/RP1A.200720.012)",
        "Host": "clientbp.ggblueshark.com",
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip"
    }
    response = requests.post(url, headers=headers, data=data_bytes)
    return jsonify({
        "status_code": response.status_code,
        "encrypted_data": formatted_encrypted_data
    })
#######GET-UPCOMING-BANNER###########
@app.route('/eventes', methods=['GET'])
async def get_urls():
    global jwt_token
    try:
        await ensure_jwt_token()
    except Exception as e:
        return jsonify({"error": f"Failed to get JWT token: {str(e)}"}), 500
    code = request.args.get("key")
    if not code:
        return jsonify({"error": "Missing key"}), 400
    if code != apis_code:
        return jsonify({"error": "Bad / Error Key !"}), 400
    api = "https://clientbp.ggblueshark.com/LoginGetSplash"
    edata = bytes.fromhex("9223af2eab91b7a150d528f657731074")
    headers = {
        'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream",
        'Expect': "100-continue",
        'Authorization': f"Bearer {jwt_token}",
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': freefire_version
    }
    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(api, headers=headers, data=edata)
        response.raise_for_status()
        urls = re.findall(r'https?://[^\s]+\.png', response.text)
        current_month = datetime.now().strftime("%B %Y")
        result = []
        for url in urls:
            clean_url = url.strip()
            event_name = clean_url.split('/')[-1].replace('_880x520_BR_pt.png', '').replace('_', ' ')     
            result.append({
            "title": event_name,
            "image_url": clean_url,
            "month": current_month
        })
        return jsonify(result)
    except httpx.HTTPStatusError as e:
        return jsonify({"error": f"HTTP error occurred: {e}"}), e.response.status_code
    except httpx.RequestError as e:
        return jsonify({"error": f"Request error occurred: {e}"}), 500
    except Exception as e:
        return jsonify({"error": f"An unexpected error occurred: {e}"}), 500
####################################
def Encrypt_ID(number):
    number = int(number)
    encoded_bytes = []
    while True:
        byte = number & 0x7F
        number >>= 7
        if number:
            byte |= 0x80
        encoded_bytes.append(byte)
        if not number:
            break
    return bytes(encoded_bytes).hex()
def encrypt_api(plain_text):
    plain_text = bytes.fromhex(plain_text)
    key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()
def parse_results(parsed_results):
    result_dict = {}
    for result in parsed_results:
        field_data = {}
        field_data['wire_type'] = result.wire_type
        if result.wire_type == "varint":
            field_data['data'] = result.data
        elif result.wire_type == "string":
            field_data['data'] = result.data
        elif result.wire_type == "bytes":
            field_data['data'] = result.data
        elif result.wire_type == 'length_delimited':
            field_data["data"] = parse_results(result.data.results)
        result_dict[result.field] = field_data
    return result_dict
####################################
import requests
async def get_player_information(uid):
    try:
        await ensure_jwt_token()
    except Exception as e:
        return {"error": f"Failed to get JWT token: {str(e)}"}

    TARGET = bytes.fromhex(encrypt_api(f"08{Encrypt_ID(uid)}1007"))
    url = "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"
    headers = {
        "Expect": "100-continue",
        "Authorization": f"Bearer {jwt_token}",
        "X-Unity-Version": "2018.4.11f1",
        "X-GA": "v1 1",
        "ReleaseVersion": freefire_version,
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; SM-N975F Build/PI)",
        "Host": "clientbp.common.ggbluefox.com",
        "Connection": "close",
        "Accept-Encoding": "gzip, deflate, br",
    }
    response = requests.post(url, headers=headers, data=TARGET)
    if response.status_code == 200:
        hex_response = binascii.hexlify(response.content).decode('utf-8')
        json_result = parse_results(Parser().parse(hex_response))
        parsed_data = json.loads(json.dumps(json_result))
        notinclan = False
        try:
            player_id = str(parsed_data["1"]["data"]["1"]["data"])
            player_likes = parsed_data["1"]["data"]["21"]["data"]
            player_name = parsed_data["1"]["data"]["3"]["data"]
            player_server = parsed_data["1"]["data"]["5"]["data"]
            player_bio = parsed_data["9"]["data"]["9"]["data"]
            player_level = parsed_data["1"]["data"]["6"]["data"]
            account_date = parsed_data["1"]["data"]["44"]["data"]
            account_date = datetime.fromtimestamp(account_date).strftime('%Y-%m-%d %H:%M:%S')
            booya_pass_level = parsed_data["1"]["data"]["18"]["data"]
            try:
                animal_name = parsed_data["8"]["data"]["2"]["data"]
            except:
                animal_name = "None"
            try:
                clan_id = parsed_data["6"]["data"]["1"]["data"]
                clan_name = parsed_data["6"]["data"]["2"]["data"]
                clan_leader = parsed_data["6"]["data"]["3"]["data"]
                clan_level = parsed_data["6"]["data"]["4"]["data"]
                clan_members_num = parsed_data["6"]["data"]["6"]["data"]
                clan_leader_name = parsed_data["7"]["data"]["3"]["data"]
                clan_leader_level = parsed_data["7"]["data"]["6"]["data"]
                clan_leader_booya_pass_level = parsed_data["7"]["data"]["18"]["data"]
                clan_leader_likes = parsed_data["7"]["data"]["21"]["data"]
                clan_leader_account_date = parsed_data["7"]["data"]["44"]["data"]
                clan_leader_account_date = datetime.fromtimestamp(clan_leader_account_date).strftime('%Y-%m-%d %H:%M:%S')
            except:
                notinclan = True

            if notinclan:
                info = {
                    "player_id": player_id,
                    "player_name": player_name,
                    "likes": player_likes,
                    "server": player_server,
                    "bio": player_bio,
                    "level": player_level,
                    "account_creation_date": account_date,
                    "booyah_pass_level": booya_pass_level,
                    "pet_name": animal_name,
                    "in_clan": False
                }
            else:
                info = {
                    "player_id": player_id,
                    "player_name": player_name,
                    "likes": player_likes,
                    "server": player_server,
                    "bio": player_bio,
                    "level": player_level,
                    "account_creation_date": account_date,
                    "booyah_pass_level": booya_pass_level,
                    "pet_name": animal_name,
                    "in_clan": True,
                    "clan_id": clan_id,
                    "clan_name": clan_name,
                    "clan_level": clan_level,
                    "clan_members": clan_members_num,
                    "clan_leader_name": clan_leader_name,
                    "clan_leader_id": clan_leader,
                    "clan_leader_level": clan_leader_level,
                    "clan_leader_likes": clan_leader_likes,
                    "clan_leader_account_date": clan_leader_account_date,
                    "clan_leader_booyah_pass_level": clan_leader_booya_pass_level
                }
            return info
        except Exception as e:
            print(e)
            return {"error": "UID IS NOT in FREE FIRE DATABASE"}
    else:
        return {"error": "Failed to fetch information."}

@app.route('/player_info', methods=['GET'])
async def player_info():
    uid = request.args.get('uid')
    code = request.args.get("key")
    if not uid or not code:
        return jsonify({" error": "Missing uid or key"}), 400
    if code != apis_code:
        return jsonify({"error": "- Bad / Error Key !"}), 400
    result = await get_player_information(uid)
    return jsonify(result)
@app.route('/check', methods=['GET'])
def get_player_info():
    user_id = request.args.get("uid")
    code = request.args.get("key")
    if not uid or not code:
        return jsonify({" error": "Missing uid or key"}), 400
    if code != apis_code:
        return jsonify({"error": "- Bad / Error Key !"}), 400
    try:
        status_response = requests.get(f'https://ff.garena.com/api/antihack/check_banned?lang=en&uid={user_id}')
        if "0" in status_response.text:
            status = f"Account Clear!"
        else:
            status = f"Account Ban!"
        cookies = {
            '_ga': 'GA1.1.2123120599.1674510784',
            '_fbp': 'fb.1.1674510785537.363500115',
            '_ga_7JZFJ14B0B': 'GS1.1.1674510784.1.1.1674510789.0.0.0',
            'source': 'mb',
            'region': 'MA',
            'language': 'ar',
            '_ga_TVZ1LG7BEB': 'GS1.1.1674930050.3.1.1674930171.0.0.0',
            'datadome': '6h5F5cx_GpbuNtAkftMpDjsbLcL3op_5W5Z-npxeT_qcEe_7pvil2EuJ6l~JlYDxEALeyvKTz3~LyC1opQgdP~7~UDJ0jYcP5p20IQlT3aBEIKDYLH~cqdfXnnR6FAL0',
            'session_key': 'efwfzwesi9ui8drux4pmqix4cosane0y',
        }
        headers = {
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive',
            'Origin': 'https://shop2game.com',
            'Referer': 'https://shop2game.com/app/100067/idlogin',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'User-Agent': 'Mozilla/5.0 (Linux; Android 11; Redmi Note 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Mobile Safari/537.36',
            'accept': 'application/json',
            'content-type': 'application/json',
            'sec-ch-ua': '"Chromium";v="107", "Not=A?Brand";v="24"',
            'sec-ch-ua-mobile': '?1',
            'sec-ch-ua-platform': '"Android"',
            'x-datadome-clientid': '20ybNpB7Icy69F~RH~hbsvm6XFZADUC-2_--r5gBq49C8uqabutQ8DV_IZp0cw2y5Erk-KbiNZa-rTk1PKC900mf3lpvEP~95Pmut_FlHnIXqxqC4znsakWbqSX3gGlg',
        }
        json_data = {
            'app_id': 100067,
            'login_id': f'{user_id}',
            'app_server_id': 0,
        }
        info_response = requests.post(
            'https://shop2game.com/api/auth/player_id_login',
            cookies=cookies,
            headers=headers,
            json=json_data
        )
        if info_response.status_code == 200:
            player_info = info_response.json()
            return jsonify({
                "▶DEV": "ProjectS FoxX!!",
                "▶PLAYER UID": user_id,
                "▶PLAYER REGION": f"{player_info['region']}",
                "▶PLAYER NAME": f"{player_info['nickname']}",
                "▶PLAYER STATUS": status,
            })
        else:
            return jsonify({"error": f"Failed to fetch player info: {info_response.status_code}"}), 400
    except Exception as e:
        return jsonify({"error": f"Error fetching player info: {e}"}), 500
####################################


key = "Fox-7CdxP"

@app.route('/site_bio', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        uid = request.form['uid']
        password = request.form['password']
        bio_msg = request.form['bio_msg']
        jwt_token = request.form['jwt_token'].strip()

        # If user did not provide a JWT Token, fetch it automatically
        if not jwt_token:
            jwt_api = f"https://trickzqw-peach.vercel.app/api/oauth_guest?uid={uid}&password={password}"
            res_jwt = requests.get(jwt_api)

            if res_jwt.status_code == 200:
                res_jwt = res_jwt.json()
                jwt_token = res_jwt["token"]
            else:
                return render_template_string(error_page, message="⚠️ Invalid UID or Password, or API is down.")

        # Change Bio using the JWT Token
        bio_api = f"https://projects-fox-apis.vercel.app/long_bio?bio={bio_msg}&token={jwt_token}&key={key}"
        res_bio = requests.get(bio_api)

        if res_bio.status_code == 200:
            return render_template_string(success_page, uid=uid, bio_msg=bio_msg)
        else:
            return render_template_string(error_page, message="❌ Failed to change the bio. Please try again.")

    return render_template_string(main_page)

# ===================[ Success Page ]===================
success_page = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Bio Changed Successfully ✅</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background: #2e2e2e; color: white; text-align: center; }
        .card { background: #3a3a3a; color: white; box-shadow: 0px 0px 15px rgba(255, 255, 255, 0.1); }
        .footer { position: fixed; bottom: 0; width: 100%; background: rgba(0, 0, 0, 0.5); color: white; text-align: center; padding: 10px 0; }
    </style>
</head>
<body>
    <div class="container mt-5">
        <div class="card p-4 mx-auto" style="max-width: 500px;">
            <h2 class="mb-3">✅ Bio Changed Successfully!</h2>
            <p><strong>UID:</strong> <span class="text-success">{{ uid }}</span></p>
            <p><strong>New Bio:</strong></p>
            <div class="alert alert-success">{{ bio_msg }}</div>
            <a href="/" class="btn btn-primary mt-3">🔄 Change Again</a>
        </div>
    </div>
    <div class="footer">©ProjectS FoxX!!</div>
</body>
</html>
'''

# ===================[ Error Page ]===================
error_page = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Error ❌</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background: #2e2e2e; color: white; }
        .container { margin-top: 100px; }
        .footer { position: fixed; bottom: 0; width: 100%; background: rgba(0, 0, 0, 0.5); color: white; text-align: center; padding: 10px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="alert alert-danger text-center">
            <h1 class="display-4">⚠️ Error!</h1>
            <p class="lead">{{ message }}</p>
            <a href="/" class="btn btn-light mt-3">🔄 Try Again</a>
        </div>
    </div>
    <div class="footer">©ProjectS FoxX!!</div>
</body>
</html>
'''

# ===================[ Main Page ]===================
main_page = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Change Bio</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background: #2e2e2e; color: white; }
        .card { background: #3a3a3a; color: white; }
        .footer { position: fixed; bottom: 0; width: 100%; background: rgba(0, 0, 0, 0.5); color: white; text-align: center; padding: 10px 0; }
    </style>
    <script>
        document.addEventListener('contextmenu', event => event.preventDefault());
        document.addEventListener("keydown", function(event) {
            if (event.keyCode == 123 || (event.ctrlKey && event.shiftKey && (event.keyCode == 73 || event.keyCode == 74))) {
                event.preventDefault();
            }
        });
    </script>
</head>
<body>
    <div class="container mt-5">
        <div class="card mx-auto p-4" style="max-width: 500px;">
            <h2 class="text-center">✏️ Change Bio</h2>
            <form method="POST">
                <div class="mb-3">
                    <label for="uid" class="form-label">UID:</label>
                    <input type="text" class="form-control" id="uid" name="uid">
                </div>
                <div class="mb-3">
                    <label for="password" class="form-label">Password:</label>
                    <input type="password" class="form-control" id="password" name="password">
                </div>
                <div class="mb-3">
                    <label for="jwt_token" class="form-label">JWT Token (Optional):</label>
                    <input type="text" class="form-control" id="jwt_token" name="jwt_token">
                    <small class="text-muted">Leave blank to fetch it automatically.</small>
                </div>
                <div class="mb-3">
                    <label for="bio_msg" class="form-label">New Bio Message:</label>
                    <input type="text" class="form-control" id="bio_msg" name="bio_msg" required>
                </div>
                <button type="submit" class="btn btn-success w-100">✅ Change Bio</button>
            </form>
        </div>
    </div>
    <div class="footer">©ProjectS FoxX!!</div>
</body>
</html>
'''
####################################
def fetcch_events():
    url = "https://projects-fox-apis.vercel.app/eventes?key=Fox-7CdxP"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    return []
def filteer_events(events):
    excluded_titles = [
        "Anno Multibind en.png",
        "LcustserEN.png",
        "News Anno Others - Survey - Tier 1 - Always On Survey ennew.png",
        "News Anno Product Marketing - Web Event - Tier 1 - Redeem Your Codes en.png"
    ]
    filtered_events = [event for event in events if event["title"] not in excluded_titles]
    return filtered_events
@app.route('/site_events')
def iidex():
    events = fetcch_events()
    filtered_events = filteer_events(events)
    html_content = """
    <!DOCTYPE html>
    <html lang="ar">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>أحداث الشهر</title>
        <style>
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background-color: #f8f9fa;
                margin: 0;
                padding: 0;
                color: #333;
            }
            .container {
                max-width: 1200px;
                margin: 0 auto;
                padding: 20px;
            }
            h1 {
                text-align: center;
                font-size: 2.5rem;
                margin-bottom: 30px;
                color: #2c3e50;
            }
            .events-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                gap: 20px;
            }
            .event-card {
                background-color: #fff;
                border-radius: 10px;
                box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
                overflow: hidden;
                transition: transform 0.3s ease, box-shadow 0.3s ease;
            }
            .event-card:hover {
                transform: translateY(-5px);
                box-shadow: 0 8px 16px rgba(0, 0, 0, 0.2);
            }
            .event-card img {
                width: 100%;
                height: 200px;
                object-fit: cover;
            }
            .event-info {
                padding: 20px;
            }
            .event-info h2 {
                margin: 0 0 10px;
                font-size: 1.5rem;
                color: #34495e;
            }
            .event-info p {
                margin: 0;
                color: #7f8c8d;
                font-size: 1rem;
            }
            footer {
                text-align: center;
                margin-top: 40px;
                padding: 20px;
                background-color: #2c3e50;
                color: #fff;
                font-size: 0.9rem;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>أحداث اليوم</h1>
            <div class="events-grid">
                {% for event in filtered_events %}
                <div class="event-card">
                    <img src="{{ event.image_url }}" alt="{{ event.title }}">
                    <div class="event-info">
                        <h2>{{ event.title }}</h2>
                        <p>{{ event.month }}</p>
                    </div>
                </div>
                {% endfor %}
            </div>
        </div>
        <footer>
            ©ProjectS FoxX!!
        </footer>
    </body>
    </html>
    """
    return render_template_string(html_content, filtered_events=filtered_events)
#############StartApi#################
if __name__ == '__main__':
    asyncio.run(startup())
    app.run(host='0.0.0.0', port=1882)