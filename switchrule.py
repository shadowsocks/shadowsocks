def getKeys():
	return ['port', 'u', 'd', 'transfer_enable', 'passwd', 'enable' ]
	#return ['port', 'u', 'd', 'transfer_enable', 'passwd', 'enable', 'plan' ] # append the column name 'plan'

def isTurnOn(row):
	return True
	#return row['plan'] == 'B' # then judge here

