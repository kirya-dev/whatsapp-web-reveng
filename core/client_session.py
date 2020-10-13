#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import pickle
import base64
import curve25519


class WhatsAppSession:
    def __init__(self):
        self.client_id = base64.b64encode(os.urandom(16))
        self.client_token = None
        self.server_ref = None
        self.server_token = None
        self.browser_token = None
        self.number = None
        self.nickname = None

        self.secret = None
        self.shared_secret = None
        self.public_key = None
        self.private_key = None
        self.enc_key = None
        self.mac_key = None

    def get_pure_number(self):
        return self.number.split('@')[0] if self.number is not None else None

    def save_to_file(self):
        data = {
            'number': self.number,
            'nickname': self.nickname,
            'client_id': self.client_id,
            'client_token': self.client_token,
            'server_ref': self.server_ref,
            'server_token': self.server_token,
            'private_key': self.private_key.private,
            'enc_key': self.enc_key,
            'mac_key': self.mac_key,
        }

        with open('wa_sessions/session_' + self.get_pure_number() + '.json', 'wb') as out_file:
            pickle.dump(data, out_file)

    @staticmethod
    def load_by_number(number):
        with open('wa_sessions/session_' + number + '.json', 'rb') as in_file:
            data = pickle.load(in_file)

            session = WhatsAppSession()
            session.number = data['number']
            session.nickname = data['nickname']
            session.client_id = data['client_id']
            session.client_token = data['client_token']
            session.server_ref = data['server_ref']
            session.server_token = data['server_token']
            session.private_key = curve25519.keys.Private(data['private_key'])
            session.public_key = session.private_key.get_public()
            session.enc_key = data['enc_key']
            session.mac_key = data['mac_key']

            return session
