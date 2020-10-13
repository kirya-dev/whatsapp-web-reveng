#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import io
import base64
import binascii
import threading
import websocket
import pyqrcode
import curve25519

from utils import cryptography
from utils.utils import *
from binary.defines import WAWebMessageInfo, WAMetrics, WAFlags

WHATSAPP_WEB_VERSION = '2,2043,8'

reload(sys)
sys.setdefaultencoding('utf-8')


class RestoreSessionStatus:
    OK = 200
    UNPAIRED_PHONE = 401
    ACCESS_DENIED = 403
    ALREADY_LOGGED = 405
    ALREADY_LOGGED_ANOTHER_LOCATION = 409


class WhatsAppWebClient:
    # TODO make as dict events?
    on_open_callback = None
    on_error_callback = None
    on_welcome_callback = None
    on_close_callback = None

    def __init__(self, session):
        self.ws = None
        self.ws_tread = None
        self.mess_queue = {}  # maps message tags (provided by WhatsApp)
        self.session = session

        self.is_logged = False
        self.is_connected = False
        self.now = getTimestamp()
        self.current_epoch = '0'
        self.current_sequence = '0'

        websocket.enableTrace(True)

    def _on_open(self):
        logger('WhatsAppWebClient: Websocket opened.')

        self.is_connected = True

        if self.on_open_callback is not None:
            self.on_open_callback()

    def _on_error(self, error):
        logger('WhatsAppWebClient: Websocket error.', error)

        if self.on_error_callback is not None:
            self.on_error_callback(error)

    def _on_close(self):
        logger('WhatsAppWebClient: Websocket closed.')

        self.is_logged = False
        self.is_connected = False
        if self.on_close_callback is not None:
            self.on_close_callback(self.on_close_callback)

    def _on_message(self, raw_message):
        json_obj = None
        json_bin_obj = None
        message_parts = raw_message.split(',', 1)
        mess_tag = message_parts[0]

        # Handle ACK
        if raw_message[-1] == ',':
            logger('WhatsAppWebClient: Received ACK by tag `' + mess_tag + '`')
            return

        message_content = message_parts[1] if len(message_parts) == 2 else ''

        # Try decode message if JSON or Binary
        if message_content != '':
            try:
                json_obj = json.loads(message_content)
            except ValueError:
                json_bin_obj = cryptography.decrypt_node(message_content, self.session.mac_key, self.session.enc_key)

        logger('WhatsAppWebClient: Received DATA by tag `' + mess_tag + '`', console_json_colorize(json_obj if json_obj is not None else json_bin_obj))

        # Run handling for messages in queue:
        if mess_tag in self.mess_queue:
            self._handle_queue_message(mess_tag, json_obj)
            return

        # Run handling for binary messages is set:
        if json_bin_obj is not None:
            self._handle_binary_message(mess_tag, json_bin_obj)
            return

        # No handling for empty messages:
        if json_obj is None or isinstance(json_obj, list) is False:
            return

        # Run handling for other responses:
        if json_obj[0] == 'Cmd':
            cmd_type = json_obj[1]['type']
            if cmd_type == 'challenge':
                if self.session.mac_key is None:
                    raise ValueError('mac_key is None')

                data = json_obj[1]['challenge']
                data = base64.b64decode(data)
                data = cryptography.HmacSha256(self.session.mac_key, data)
                data = base64.b64encode(data)

                challenge_message = mess_tag + ',["admin","challenge","' + data + '","' + \
                                    self.session.server_token + '","' + \
                                    self.session.client_id + '"]'
                self.ws.send(challenge_message)

            elif cmd_type == 'disconnect':
                logger('WhatsAppWebClient: Disconnected.')
                return

            else:
                raise ValueError('Unknown Cmd type: ' + cmd_type)

        elif json_obj[0] == 'Conn':
            # TODO: not always Conn is really connected.. (((
            if 'clientToken' not in json_obj[1]:
                logger('WhatsAppWebClient: ERROR: no clientToken.')
                return

            self.session.client_token = json_obj[1]['clientToken']
            self.session.server_token = json_obj[1]['serverToken']
            self.session.browser_token = json_obj[1]['browserToken']
            self.session.number = json_obj[1]['wid']
            self.session.nickname = json_obj[1]['pushname']

            if 'secret' in json_obj[1]:
                self.session.secret = base64.b64decode(json_obj[1]['secret'])
                self.session.shared_secret = self.session.private_key.get_shared_key(
                    curve25519.Public(self.session.secret[:32]), lambda a: a)
                sse = cryptography.HKDF(self.session.shared_secret, 80)
                hmac_validation = cryptography.HmacSha256(sse[32:64], self.session.secret[:32] + self.session.secret[64:])
                if hmac_validation != self.session.secret[32:64]:
                    raise ValueError('Hmac mismatch')

                keys_encrypted = sse[64:] + self.session.secret[64:]
                keys_decrypted = cryptography.AESDecrypt(sse[:32], keys_encrypted)
                self.session.enc_key = keys_decrypted[:32]
                self.session.mac_key = keys_decrypted[32:64]

                self.session.save_to_file()

            logger('WhatsAppWebClient: Welcome ' + self.session.nickname + '! (' + self.session.number + ')')

            self.is_logged = True
            self._start_keep_alive()
            if self.on_welcome_callback is not None:
                self.on_welcome_callback()

        elif json_obj[0] == 'Stream':
            pass  # TODO

        elif json_obj[0] == 'Props':
            pass  # TODO

        elif json_obj[0] == 'Msg':
            pass  # TODO

        elif json_obj[0] == 'Presence':
            pass  # TODO

    def _handle_queue_message(self, mess_tag, json_obj):
        pend = self.mess_queue[mess_tag]
        pend_callback = pend['callback'] if 'callback' in pend and pend['callback'] is not None else lambda params: ()
        pend_desc = pend['desc']

        if pend_desc == '_message_sending':
            logger('WhatsAppWebClient: Message sent')
            pend_callback({'status': True})

        elif pend_desc == '_restore_session':
            if len(json_obj) == 1:
                resp_status = json_obj['status']
                if resp_status == RestoreSessionStatus.OK:
                    logger('WhatsAppWebClient: Session successfully restored!')

                    pend_callback({'status': True})
                else:
                    logger('WhatsAppWebClient: Challenge requested.')
            else:
                # Noting to do.
                pass

        elif pend_desc == '_login':
            logger('WhatsAppWebClient: Login (accept qr code)')
            self.session.server_ref = json_obj['ref']

            self.session.private_key = curve25519.Private()
            self.session.public_key = self.session.private_key.get_public()

            qr_code_contents = self.session.server_ref + "," + base64.b64encode(
                self.session.public_key.serialize()) + "," + self.session.client_id

            # from https://github.com/mnooner256/pyqrcode/issues/39#issuecomment-207621532
            svg_buffer = io.BytesIO()
            pyqrcode.create(qr_code_contents, error='L').svg(svg_buffer, scale=6, background='rgba(0,0,0,0.0)',
                                                             module_color='#122E31', quiet_zone=0)
            pend_callback({'image': "data:image/svg+xml;base64," + base64.b64encode(svg_buffer.getvalue()),
                           "content": qr_code_contents})

    def _handle_binary_message(self, mess_tag, json_obj):
        pass

    def start(self):
        self.ws = websocket.WebSocketApp('wss://web.whatsapp.com/ws',
                                         on_message=lambda ws, message: self._on_message(message),
                                         on_error=lambda ws, error: self._on_error(error),
                                         on_open=lambda ws: self._on_open(),
                                         on_close=lambda ws: self._on_close(),
                                         header={'Origin: https://web.whatsapp.com'})

        self.ws_tread = threading.Thread(target=self.ws.run_forever)
        self.ws_tread.daemon = True
        self.ws_tread.start()

    def generate_qr_code(self, callback=None):
        mess_tag = self._next_sequence_tag()
        self.mess_queue[mess_tag] = {'desc': "_login", "callback": callback}
        message = mess_tag + ',["admin","init",[' + WHATSAPP_WEB_VERSION + '],["Mhatsapp","Opera","10.15.6"],"' + \
                  self.session.client_id + '",true]'
        self.ws.send(message)

    def restore_session(self, callback=None):
        message = self._next_sequence_tag() + ',["admin","init",[' + WHATSAPP_WEB_VERSION + '],["Mhatsapp","Opera","10.15.6"],"' + \
                  self.session.client_id + '",true]'
        self.ws.send(message)

        mess_tag = self._next_sequence_tag()
        self.mess_queue[mess_tag] = {'desc': '_restore_session', 'callback': callback}
        message = mess_tag + ',["admin","login","' + self.session.client_token + '", "' + self.session.server_token + '", "' + self.session.client_id + '", "takeover"] '
        self.ws.send(message)

    def send_text_message(self, number, text, callback=None):
        self._ensure_logged()
        logger('WhatsAppWebClient: Sending to "' + number + '"')

        # Generate 20 length id
        mess_tag = '3EB0' + binascii.hexlify(os.urandom(8)).upper()
        mess_encoded = WAWebMessageInfo.encode({
            'key': {'fromMe': True, 'remoteJid': number + '@s.whatsapp.net', 'id': mess_tag},
            'message': {'conversation': text},
            'messageTimestamp': getTimestamp(),
            'status': '1',
        })
        mess_node = [
            'action',
            {'type': 'relay', 'epoch': self._next_epoch()},
            [
                ['message', None, mess_encoded]
            ]
        ]

        self.mess_queue[mess_tag] = {'desc': '_message_sending', 'callback': callback}

        self._send_bin(mess_node, [WAMetrics.MESSAGE, WAFlags.IGNORE], mess_tag=mess_tag)

    def get_chat_message(self, with_number):
        # Get history of messages by one chat
        mess_node = ['query', {'count': '50',
                               'index': '68F1EBA95A4E87E69F6CFC14180235AC',
                               'kind': 'before',
                               'jid': with_number + '@c.us',
                               'epoch': self._next_epoch(),
                               'owner': 'false',
                               'type': 'message',
                               },
                     None
                     ]
        self._send_bin(mess_node, [WAMetrics.QUERY_MESSAGES, WAFlags.IGNORE], mess_tag=self._next_sequence_tag(True) + ',')

    def disconnect(self):
        self._ensure_connected()

        # WhatsApp server closes connection automatically when client wants to disconnect
        self.ws.send('goodbye,,["admin","Conn","disconnect"]')
        self.is_connected = False
        # time.sleep(0.5)
        # self.activeWs.close()

    def _send_bin(self, mess_node, mess_args, mess_tag=None):
        tag = self._next_sequence_tag(is_short=True) if mess_tag is None else mess_tag

        payload = cryptography.encrypt_and_mac(tag, mess_node, mess_args, self.session.mac_key, self.session.enc_key)

        self.ws.send(payload, websocket.ABNF.OPCODE_BINARY)

    def _ensure_connected(self):
        if self.is_connected is False:
            raise ValueError('Not connected')

    def _ensure_logged(self):
        self._ensure_connected()
        if self.is_logged is False:
            raise ValueError('Not logged')

    def _start_keep_alive(self):
        self._send_bin(['query', {'type': 'contacts', 'epoch': '1'}, None], [WAMetrics.QUERY_CONTACTS, WAFlags.IGNORE])
        self._send_bin(['query', {'type': 'chat', 'epoch': '1'}, None], [WAMetrics.QUERY_CHAT, WAFlags.IGNORE])
        self._send_bin(['query', {'type': 'status', 'epoch': '1'}, None], [WAMetrics.QUERY_STATUS, WAFlags.IGNORE])
        self._send_bin(['query', {'type': 'quick_reply', 'epoch': '1'}, None],
                       [WAMetrics.QUERY_QUICK_REPLIES, WAFlags.IGNORE])
        self._send_bin(['query', {'type': 'label', 'epoch': '1'}, None], [WAMetrics.QUERY_LABELS, WAFlags.IGNORE])
        self._send_bin(['query', {'type': 'emoji', 'epoch': '1'}, None], [WAMetrics.QUERY_EMOJI, WAFlags.IGNORE])
        self._send_bin(['action', {'type': 'set', 'epoch': '1'}, [['presence', {'type': 'available'}, None]]],
                       [WAMetrics.PRESENCE, 160])

        def keep_alive():
            while self.is_connected:
                time.sleep(20)
                self.ws.send('?,,')

        thd = threading.Thread(target=keep_alive)
        thd.daemon = True
        thd.start()

    def _next_sequence_tag(self, is_short=False):
        prev = self.current_sequence
        self.current_sequence = str(int(self.current_sequence) + 1)

        return str(self.now % 1000 if is_short else self.now) + '.--' + prev

    def _next_epoch(self):
        prev = self.current_epoch
        self.current_epoch = str(int(self.current_epoch) + 1)

        return prev
