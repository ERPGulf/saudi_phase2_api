import os
from twilio.rest import Client
account_sid = 'ACbfd204d4101882f6a20c4e06136d2bb3'
auth_token = '358440022aff2ce4006f15ceeba2bf25'
client = Client(account_sid, auth_token)
message = client.messages.create(
  from_='+18789999387',
  body='hello testing ..',
  to='+917306204060'
)
print(message.sid)

