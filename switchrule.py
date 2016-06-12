from configloader import load_config, get_config

def getKeys():
	load_config()
	key_list = ['port', 'u', 'd', 'transfer_enable', 'passwd', 'enable' ]
	if get_config().API_INTERFACE == 'sspanelv3':
		key_list += ['method']
	return key_list
	#return key_list + ['plan'] # append the column name 'plan'

def isTurnOn(row):
	return True
	#return row['plan'] == 'B' # then judge here

