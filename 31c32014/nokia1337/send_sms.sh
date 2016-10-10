#!/bin/sh

./send_sms.py 123456 313373 "SMS TEXT" | nc 127.0.0.1 4445
