import base64
import json

from utils.cryptography import *

"""
 In browser please dump this field:
     JSON.parse(window.localStorage.getItem('WASecretBundle'))

 and insert here:
"""
mac_key = "LlOtQLOe0AOX3Nvp/3mPIkfHQuB0kEbKsNWYm9l9ppU="
enc_key = "bgChqDs7oAGVehrqcUCyVb3rP5H8xcY2T5FQgZTHoDs="

# Copy (incoming) message as base64
mess = 'M0VCMEZEN0ZGMjg4Qzc5QjJCMTcsEIDaPlEVXgkwWyCsDLsqktS5l+DUZcGNXp8jOvV5hnSXHjbHeGb2gdJk+Q8I0sV1Tth0nha5az6rxCmevaUKnXh14eIBWmMjLizcIo0gLtCESUR2bhnqXGE+NXVoS0TZJjdQdBfOgztPeqIkh7MaCp9/UDwl26HV/mhBT4kyFavwQPH0WwbwZ9TQcU1azLDXGmi6pFuNwxM4sMz6o+jyydolk3FYE3uZDwi/3Z7mhFwse/MpFoSs2qV+UiC76GYT4OpcETgyPo/OOFrBV/uR44/SD2KISu3G5U3AIqvmu3+BENpUSDrbaDFJNW7yJyWvpOG+C7GhQh64QVX88K35XCn+2HTfVUyjV9q5wvkI5MvABzxcP0g26WayGXB2gHe1bqw='

mess = base64.b64decode(mess)
mac_key = base64.b64decode(mac_key)
enc_key = base64.b64decode(enc_key)

message_parts = mess.split(',', 1)
mess_tag = message_parts[0]
mess_cont = message_parts[1]

print('tag', mess_tag)

mess_pre_bytes = map(ord, mess_cont[:2])
mess_cont = decrypt_node(mess_cont[2:], mac_key, enc_key)

print('mess_pre_bytes', mess_pre_bytes)
print('mess_cont', json.dumps(mess_cont))
