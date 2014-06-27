# -*- coding: utf-8 -*-
from __future__ import absolute_import
from io import BytesIO
from celery import shared_task
from django.utils import timezone
from django.core.files.base import ContentFile
from elect_def.models import Election, Ballot,Randomstate,Assignment, Tokens, Pdfballot
import hashlib,hmac,base64,os,binascii,subprocess, cStringIO, csv, zipfile, requests, qrcode,codecs
from Crypto.Cipher import AES
from Crypto import Random
from django.core.files import File
from reportlab.lib.utils import ImageReader
from reportlab.pdfgen import canvas
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont


BB_URL = "http://tal.di.uoa.gr/finer/"
CLIENT_URL = "http://tal.di.uoa.gr/ea/client/"
Ballot_URL = "http://tal.di.uoa.gr/ea/pdf/"

 #support UTF-8
env = os.environ
env['PYTHONIOENCODING'] = 'utf-8'

#the size of hamc and AES
RSIZE = 32
KSIZE = 16

def addbars(code):
        output = ''
        for i in range(3):
                if i != 0:
                        output+="-"
                output+=code[i*4:(i+1)*4]
        return output

def removebars(code):
        return code[0:4]+code[5:9]+code[10:len(code)]

def base36encode(number, alphabet='0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'):
    """Converts an integer to a base36 string."""
    if not isinstance(number, (int, long)):
        raise TypeError('number must be an integer')
    base36 = ''
    sign = ''
    if number < 0:
        sign = '-'
        number = -number
    if 0 <= number < len(alphabet):
        return sign + alphabet[number]
    while number != 0:
        number, i = divmod(number, len(alphabet))
        base36 = alphabet[i] + base36
    return sign + base36

def base36decode(number):
    return int(number, 36)

def pad(s):
    return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

def encrypt(message, key, key_size=256):
    message = pad(message)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(message)

def decrypt(ciphertext, key):
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext[AES.block_size:])
    return plaintext.rstrip(b"\0")


@shared_task
def prepare_ballot(e, total, n, emails, keyemails, intpdf):
    #print "test...creating ballot.."
    #create ballots
    for v in range(100,total+100):
        serial = str(v)
        key = os.urandom(RSIZE)
	skey = base64.b64encode(key)
        codes = ["",""]
        recs = ["",""]
	votes = ["",""]
	ciphers = ["",""]
        for ab in range(2):
	    p = subprocess.Popen(["sh","/var/www/finer/EC-ElGamal/GenPerm.sh", str(n)],stdout=subprocess.PIPE,stderr=subprocess.PIPE, env=env)
	    output,err = p.communicate()
	    votes[ab] = output
	    #read from the disk file for ciphers
	    f = open('/var/www/finer/EC-ElGamal/EC_cipher.txt')
	    lines = f.readlines()
	    f.close()
	    flag = 0
	    i = 0
	    for enc in lines:
		i+=1
		if i >= 2:
		    if i%2 == 0:
			ciphers[ab]+=" "	
		    else: #" " and "," alternating
			ciphers[ab]+=","	
		ciphers[ab]+=enc.strip()
	    for i in range(n):
    	        message = bytes(serial+str(ab)+str(i)).encode('utf-8')
    	        c = hmac.new(key, message, digestmod=hashlib.sha256).digest()
	        c1 = long(binascii.hexlify(c[0:8]), 16) #convert 64 bit string to long
	        c1 &= 0x3fffffffffffffff # 64 --> 62 bits
	        sc1 = base36encode(c1)
		while len(sc1)<12:#length padding
		    sc1 = "0"+sc1
	        r1 = long(binascii.hexlify(c[8:12]), 16) #convert 32 bit string to long
                r1 &= 0x7fffffff # 32 --> 31 bits
                sr1 = base36encode(r1)
		while len(sr1)<6:#length padding
                    sr1 = "0"+sr1
                if i > 0:
		    codes[ab]+=","
		    recs[ab]+=","
	        codes[ab]+=addbars(sc1)
	        recs[ab]+=sr1
	new_b = Ballot(election = e, serial = serial, key = skey, votes1 = votes[0],votes2 = votes[1],cipher1 = ciphers[0],cipher2 = ciphers[1], codes1 = codes[0],codes2 = codes[1],rec1 = recs[0],rec2 = recs[1])
        new_b.save()
    #mark as prepared
    e.prepared = True
    e.save()
    # assign email ballots
    #get choices
    options = e.choice_set.values('text')
    opts = [x['text'] for x in options]
    #get all the unassigned ballots
    unused = Ballot.objects.filter(election = e)# all are not used
    counter = 0
    for voter in emails:
	#generate random token
	token = long(binascii.hexlify(os.urandom(16)), 16)
        stoken = base36encode(token)#no padding 128 bit
	b = unused[counter]
	counter += 1
	email = voter.rstrip()
	assign = Assignment(election = e, vID = stoken+email, serial = b.serial)
	assign.save()
	#mark as used
	b.used = True
	b.save()
	#store token
	new_t = Tokens(election = e, token = stoken, email = email)
	new_t.save()
	#get codes and options
    	codes1 = b.codes1.split(',')
    	codes2 = b.codes2.split(',')
    	rec1 = b.rec1.split(',')
    	rec2 = b.rec2.split(',')
    	perm1 = b.votes1.split(',')
    	perm2 = b.votes2.split(',')
    	#sort according to perm1
    	sorted1 = sorted(zip(perm1,codes1,rec1))
    	sorted2 = sorted(zip(perm2,codes2,rec2))
    	ballot_code1 = [y for (x,y,z) in sorted1]
    	ballot_code2 = [y for (x,y,z) in sorted2]
    	ballot_rec1 = [z for (x,y,z) in sorted1]
    	ballot_rec2 = [z for (x,y,z) in sorted2]
    	#send email for the first time
    	emailbody = "Hello,\n\nHere is your ballot.\n"
	emailbody+= "================================================\nSerial Number: "+b.serial+"\n"
	emailbody+= "================================================\nBallot A: \n"
	for i in range(len(opts)):
	    emailbody+= "Votecode: "+ballot_code1[i]+"  Receipt: "+ballot_rec1[i]+ "  Option: "+opts[i]+"\n"
        emailbody+= "================================================\nBallot B: \n"
        for i in range(len(opts)):
            emailbody+= "Votecode: "+ballot_code2[i]+"  Receipt: "+ballot_rec2[i]+ "  Option: "+opts[i]+"\n"
	emailbody+= "================================================\n"
    	emailbody+= "\nVBB url: "+BB_URL+"vbb/"+e.EID+"/\n"
    	emailbody+= "ABB url: "+BB_URL+"abb/"+e.EID+"/\n"
	emailbody+= "Client url: "+CLIENT_URL+e.EID+"/"+stoken+"/\n"
    	emailbody+= "\nFINER Ballot Distribution Server\n"
    	#send email		
    	p = subprocess.Popen(["sudo","/var/www/finer/bingmail.sh","Ballot for Election: "+e.question, emailbody,email],stdout=subprocess.PIPE,stderr=subprocess.PIPE, env=env)
    	output,err = p.communicate()
###################
#pdf ballots
    zip_buffer = cStringIO.StringIO()
    zfile = zipfile.ZipFile(zip_buffer,'w')
    for i in range(intpdf):
	#generate random token
	token = long(binascii.hexlify(os.urandom(16)), 16)
        stoken = base36encode(token)#no padding 128 bit
	b = unused[counter]
	counter += 1
	email = "pdf"+str(i)
	assign = Assignment(election = e, vID = stoken+email, serial = b.serial)
	assign.save()
	#mark as used
	b.used = True
	b.save()
	#store token
	new_t = Tokens(election = e, token = stoken, email = email)
	new_t.save()
	#get codes and options
    	codes1 = b.codes1.split(',')
    	codes2 = b.codes2.split(',')
    	rec1 = b.rec1.split(',')
    	rec2 = b.rec2.split(',')
    	perm1 = b.votes1.split(',')
    	perm2 = b.votes2.split(',')

    	#sort according to perm1
    	sorted1 = sorted(zip(perm1,codes1,rec1))
    	sorted2 = sorted(zip(perm2,codes2,rec2))
    	ballot_code1 = [y for (x,y,z) in sorted1]
    	ballot_code2 = [y for (x,y,z) in sorted2]
    	ballot_rec1 = [z for (x,y,z) in sorted1]
    	ballot_rec2 = [z for (x,y,z) in sorted2]
	#generate the pdf
	buffer = cStringIO.StringIO()
    	# Create the PDF object, using the IO object as its "file."
	  #register ttf fonts
 	ttffont='/usr/share/fonts/truetype/ttf-liberation/'
    	pdfmetrics.registerFont(TTFont('LiberationSans', ttffont+'LiberationSans-Regular.ttf'))
    	pdfmetrics.registerFont(TTFont('LiberationSansBd', ttffont+'LiberationSans-Bold.ttf'))
    	pdfmetrics.registerFont(TTFont('LiberationSansIt', ttffont+'LiberationSans-Italic.ttf'))
    	pdfmetrics.registerFont(TTFont('LiberationSansBI', ttffont+'LiberationSans-BoldItalic.ttf'))
    	p = canvas.Canvas(buffer)
	# Draw things on the PDF. Here's where the PDF generation happens.
	p.setFont("LiberationSans", 10)
	height = 800
    	p.drawString(60, height, "================================================")
	height -=20
	tempstr = "Σειριακός αριθμός: "+b.serial
#    	p.drawString(60, height, tempstr.decode('utf-8'))
	height -=20
 #   	p.drawString(60, height, "================================================")
        height -=20
  #  	p.drawString(60, height, "Ψηφοδέλτιο Α:".decode('utf-8'))
        height -=20
	for j in range(len(opts)):
	    tempstr = "Κωδικός: "+ballot_code1[j]+"  Απόδειξη: "+ballot_rec1[j]+ "  Υποψήφιος: "+opts[j]
#	    p.drawString(60, height, tempstr.decode('utf-8'))
	    height -=20
#        p.drawString(60, height, "================================================")
        height -=20
 #       p.drawString(60, height, "Ψηφοδέλτιο B:".decode('utf-8'))
	height -=20
        for j in range(len(opts)):
            tempstr = "Κωδικός: "+ballot_code2[j]+"  Απόδειξη: "+ballot_rec2[j]+ "  Υποψήφιος: "+opts[j]
  #          p.drawString(60, height, tempstr.decode('utf-8'))
            height -=20
        p.drawString(60, height, "================================================")
        height -=20
	tempstr = "Διέυθυνση υποβολής ψήφου και ανακοίνωσης αποτελέσματος: "+BB_URL+"vbb/"+e.EID+"/"
   # 	p.drawString(60, height,tempstr.decode('utf-8'))
	height -=20
	tempstr = "Διεύθυνση επαλήθευσης εκλογικής διαδικασίας: "+BB_URL+"abb/"+e.EID+"/"
    #	p.drawString(60, height, tempstr.decode('utf-8'))
	height -=20
    	p.drawString(60, height, "Διεύθυνση εξυπηρέτησης ψηφοφόρου:".decode('utf-8'))
	height -=20
    	p.drawString(60, height,CLIENT_URL+e.EID+"/"+stoken+"/")
	height -=20  
    	p.drawString(60, 100, "Εξυπηρετητής Διανομής Ψηφοδελτίων FINER".decode('utf-8'))
    	img = qrcode.make(CLIENT_URL+e.EID+"/"+stoken+"/")
    	output = cStringIO.StringIO() ## temp QR file
    	img.save(output,'PNG')
    	output.seek(0) #rewind the data
    	image = ImageReader(output)
    	p.drawImage(image,200,120,width=180, height=180)
    	# Close the PDF object cleanly, and we're done.
    	p.showPage()
    	p.save()
	output.close()
	#save pdf
        zfile.writestr("Ballots/"+str(i)+".pdf", buffer.getvalue())
        buffer.close()
    new_pdf = Pdfballot(election = e, token = stoken)
    new_pdf.save()
    zfile.close()
    new_pdf.pdf.save("Ballots"+e.EID+".zip",ContentFile(zip_buffer.getvalue()))
    zip_buffer.close()
#send the PDF ballot link
    emailbody = "Hello,\n\nYour ballots are generated. You can download them now.\n"
    emailbody+= "URL: "+Ballot_URL+e.EID+"/"+stoken+"/\n"
    emailbody+= "\nFINER Ballot Distribution Server\n"
    #send email             
    p = subprocess.Popen(["sudo","/var/www/finer/bingmail.sh","PDF Ballots for Election: "+e.question, emailbody,e.c_email],stdout=subprocess.PIPE,stderr=subprocess.PIPE, env=env)
    output,err = p.communicate()	

########################################
	
    #send ABB CSV data
    #random key for column 1
    k1 = os.urandom(KSIZE)
    sk1 = base64.b64encode(k1)
    new_r = Randomstate(election = e, notes = "k1",random = sk1)
    new_r.save()

###send key to key holders
    emailbody = "Dear Key Holder,\n\n Your private key is:\n"
    emailbody+= "================================================\n"	
    emailbody+= sk1+"\n"
    emailbody+= "================================================\n"
    emailbody+= "\nYour Tally URL: "+BB_URL+"keyholder/"+e.EID+"/\n"
    emailbody+= "\nFINER  Election Authority\n"
    email = keyemails
    #send email         
    p = subprocess.Popen(["sudo","/var/www/finer/bingmail.sh","Private Key for Election Definition "+e.EID, emailbody,email],stdout=subprocess.PIPE,stderr=subprocess.PIPE, env=env)
    output,err = p.communicate()
##########################

    #create csv file and encrypt the codes
    output = cStringIO.StringIO() ## temp output file
    writer = csv.writer(output, dialect='excel')
    #first row n, k1.
    writer.writerow([str(n),sk1])
    #get all the ballots
    all_ballots = Ballot.objects.filter(election = e)
    for each in all_ballots:
	writer.writerow([each.serial,each.key])#second row serial , key.
	#encrypt codes
	temp_list = each.codes1.split(',')
	enc_list = []
	for temp in temp_list:
	    enc_list.append(base64.b64encode(encrypt(temp,k1,key_size=128)))	
	writer.writerow(enc_list)
	#write cipher
	temp_list = each.cipher1.split(',')
	writer.writerow(temp_list)
	#do the same for ballot 2
        #encrypt codes
        temp_list = each.codes2.split(',')
        enc_list = []
        for temp in temp_list:
            enc_list.append(base64.b64encode(encrypt(temp,k1,key_size=128)))
        writer.writerow(enc_list)
        #write cipher
        temp_list = each.cipher2.split(',')
        writer.writerow(temp_list)
    #post
    reply = requests.post(BB_URL+'abb/'+e.EID+'/upload/',files = {'inputfile':ContentFile(output.getvalue(),name = "init.csv")})
    
    #close
    output.close()
    return reply






