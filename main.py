#!/usr/bin/env python
# -*- coding: utf-8 -*-

import threading

from core.client import WhatsAppWebClient
from core.client_registry import ClientRegistry
from core.client_session import WhatsAppSession
from utils.utils import *

from flask import Flask, request

reload(sys)
sys.setdefaultencoding('utf-8')

# Run Flask
app = Flask(__name__)

client_registry = ClientRegistry()

KIRYA_DEV_NUMBER = '79614000145'
MESSAGE_SEND_TIMEOUT = 2.0  # Seconds


@app.route('/')
def get_index():
    data = {'image': ''}

    number = str(request.args.get('number', KIRYA_DEV_NUMBER))

    is_session_restoring = False
    try:
        session = WhatsAppSession.load_by_number(number)
        is_session_restoring = True
    except IOError:
        # TODO: filter on error on un exists file
        session = WhatsAppSession()

    client = client_registry.find_by_id(session.client_id)

    if client is not None:
        session = client.session
    else:
        data_ready = threading.Event()

        client = WhatsAppWebClient(session)

        if is_session_restoring:
            def respond_login(resp_data):
                data_ready.set()

            client.on_open_callback = lambda: client.restore_session(respond_login)
        else:
            def respond_qr_data(resp_data):
                data['image'] = resp_data['image']
                data_ready.set()

            client.on_open_callback = lambda: client.generate_qr_code(respond_qr_data)

        client.start()
        client_registry.register(client)

        data_ready.wait(timeout=15)

    return '<img src="' + data['image'] + '"> id: ' + session.client_id
    # return {
    #     'status': True,
    #     'image': data['image'],
    #     'client_id': config.client_id,
    # }


@app.route('/send-message')
def get_send_message():
    from_number = str(request.args.get('from_number', KIRYA_DEV_NUMBER))
    to_number = str(request.args.get('to_number', KIRYA_DEV_NUMBER))
    message = request.args.get('text', 'Its test message. Current time: ' + str(time.time()))

    client = client_registry.find_by_number(from_number)

    if client is None:
        return api_response(False, 'No client registered with number: ' + from_number)

    if client.is_logged is False:
        return api_response(False, 'Client ' + from_number + ' not logged yet')

    is_ok = {'ok': False}

    # try:
    data_ready = threading.Event()

    def callback(resp_data):
        is_ok['ok'] = resp_data['status']
        data_ready.set()

    client.send_text_message(to_number, message, callback)

    data_ready.wait(timeout=MESSAGE_SEND_TIMEOUT)
    # except ValueError, exception:
    #     return api_response(False, exception.message)

    return api_response(is_ok['ok'], 'Message sent' if is_ok['ok'] else 'Message not sent')


def api_response(status, what):
    return {'status': status, 'what': what}


if __name__ == '__main__':
    app.run()
