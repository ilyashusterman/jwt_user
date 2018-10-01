import json

from bunch import Bunch


class User(Bunch):

	def __repr__(self):
		return json.dumps(self.__dict__)
