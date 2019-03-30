#!/usr/bin/python

import serial, time

def send_recv(input):
	ser.write(input+'\r')
	data = ""
	for _ in range(16):
		v = ser.readline()
		if len(v.strip()) != 0:
			data+=v
	return data.strip()

def disable_echo():
	send_recv('ATE0')

def check_pin_status():
	status = send_recv('AT+CPIN?').replace("OK","").strip()
	if status=="+CPIN: READY":
		print("PIN has been entered. Your device is already unlocked.")
	else:
		print("PIN Status Code: "+status.split("+CPIN: ")[1])

def enter_pin(pin):
	status = send_recv('AT+CPIN="'+pin+'"')
	if(status.strip()=="OK"):
		print("Success. PIN was correct. SIM Card is now unlocked.")
	else:
		print("Error. PIN has been entered already or is invalid.")

def show_sim_data():
	model = send_recv('AT+CGMM').replace("+CGMM: ","").replace("OK","").strip()
	manufacturer = send_recv('AT+CGMI').replace("+CGMI: ","").replace("OK","").strip()
	imei = send_recv('AT+CGSN').replace("OK","").strip()
	imsi = send_recv('AT+CIMI').replace("OK","").strip()
	print("Model: "+model)
	print("Manufacturer: "+manufacturer)
	print("IMEI: "+imei)
	print("IMSI: "+imsi)

def signal_quality():
	signal = send_recv('AT+CSQ').replace("OK","").strip().split('+CSQ: ')[1]
	print("Your signal Quality: "+signal.replace(" ",""))

def send_sms(phone, message):
	send_recv('AT+CMGF=1')
	status = send_recv('AT+CMGS="'+phone+'"')
	if status.strip()==">":
		code = send_recv(message+"\x1A")
	else:
		print("SMS Encoding Error.")
	print("Success. SMS Sent.")

def show_sms():
	send_recv('AT+CMGF=1')
	send_recv('AT+CPMS="SM"')
	output = send_recv('AT+CMGL="ALL"')
	if output.strip()=="OK":
		print("No SMS found.")
	else:
		print("Reading SMS...")
		output = output.split("+CMGL: ")[1:]
		for line in output:
			id = line.split(",")[0]
			phone = line.split(",")[2].replace('"','')
			time = line.split(",")[4].split("\r\n")[0].replace('"','').split("+")[0]
			msg = line.split(",")[4].split("\r\n")[1]
			print("["+id+"] "+phone+" ("+time+"): "+msg)

def del_sms(id):
	send_recv('AT+CMGF=1')
	send_recv('AT+CPMS="SM"')
	code = send_recv('AT+CMGD='+str(id))
	if code.strip()=="OK":
		print("Success. Deleted Message with ID: "+str(id)+" from SIM Card.")
	else:
		print("Error deleting SMS.")

def show_phonebook(count):
	output = send_recv('AT+CPBR=1,'+str(count)).replace("OK","").strip().replace('+CPBR: ','').splitlines()
	print("Reading Phonebook...")
	for line in output:
		line = line.replace('"','').split(",")
		id = line[0]
		number = line[1]
		scope = line[2]
		name = line[3]
		print("["+str(id)+"] "+number+" - "+name)

ser = serial.Serial('/dev/ttyUSB0', 19200, timeout=0.1)
disable_echo()

#enter_pin("1111")
check_pin_status()
signal_quality()
show_sim_data()
#send_sms("015780818983","Hallo Welt")
show_phonebook(20)
#del_sms(1)
show_sms()

ser.close()
