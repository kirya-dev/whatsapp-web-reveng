class ClientRegistry:
    def __init__(self):
        self._clients = {}

    def register(self, client):
        self._clients[client.session.client_id] = client

    def find_by_id(self, client_id):
        return self._clients[client_id] if client_id in self._clients else None

    def find_by_number(self, number):
        return next((self._clients[c_id]
                     for c_id in self._clients
                     if self._clients[c_id].session.get_pure_number() == number
                     ), None)
