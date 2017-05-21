#!/usr/bin/env python2
import json
import sys
import time

data = json.loads(sys.stdin.read())

class Serializable:
	def toJSON(self):
		return json.dumps(self,default=lambda o: o.__dict__,
            		sort_keys=True, indent=4)

class ACDOAuthData(Serializable):
	def __init__(self,at,rt):
		self.access_token=at
		self.exp_time=time.time()+1800
		self.expires_in=3600
		self.refresh_token=rt

print ACDOAuthData(data["access_token"],data["refresh_token"]).toJSON()


