from auth.config import settings
import os
import sys
import jwt

sys.path.insert(1, os.path.join(sys.path[0], '..'))


token_string = 'eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.' \
    'eyJ0eXBlIjoicmVmcmVzaF90b2tlbiIsInN1YiI6IjEiLCJleHAiOjU0OTgxMjQyOTUsImlhdCI6MTc2NTY0NDI5NX0.' \
    'JaamTkV5JkPMj_xUjpPt0zUwLO-9QkoxOIN7XmQMkkD6QsV2DBV0buBzTWhtX5MizRCNqPwniJFS56wqP4kfCg'

token_bytes = token_string.encode('utf-8')

decoded_payload = jwt.decode(token_bytes, settings.jwt_auth.public_key_path.read_text(
), algorithms=settings.jwt_auth.algorithm)

print(decoded_payload)
