# -*- coding: utf-8 -*-
from __future__ import absolute_import
from io import BytesIO
from celery import shared_task
from django.utils import timezone
from django.core.files.base import ContentFile
from elect_def.models import Election, Ballot,Keyholder,Assignment, Tokens, Pdfballot
import hashlib,hmac,base64,os,binascii,subprocess, cStringIO, csv, zipfile, requests, qrcode,codecs,struct
from Crypto.Cipher import AES
from Crypto import Random
from django.core.files import File
from reportlab.lib.utils import ImageReader
from reportlab.pdfgen import canvas
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.lib.pagesizes import letter,A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Spacer, Table, TableStyle,Image, Paragraph


BB_URL = "https://bb.elections-devel.uoa.gr/bb/"
SAMPLE_URL = "https://elections-devel.uoa.gr/ea/sample/"
CLIENT_URL = "https://elections-devel.uoa.gr/ea/client/"
Ballot_URL = "https://elections-devel.uoa.gr/ea/pdf/"

 #support UTF-8
env = os.environ
env['PYTHONIOENCODING'] = 'utf-8'

#the size of hamc and AES
RSIZE = 32
KSIZE = 16


def long_to_bytes (val, endianness='big'):
    width = val.bit_length()
    width += 8 - ((width % 8) or 8)
    fmt = '%%0%dx' % (width // 4)
    s = binascii.unhexlify(fmt % val)
    if endianness == 'little':
        s = s[::-1]
    return s


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
    #print total
    #print n

    #create ballots
    for v in range(100,total+100):
        serial = str(v)
        key = os.urandom(RSIZE)
	skey = base64.b64encode(key)
        codes = ["",""]
        recs = ["",""]
	votes = ["",""]
	ciphers = ["",""]
	plains = ["",""]
	decom = ["",""]
        for ab in range(2):
	    #print "script run"

	    p = subprocess.Popen(["sh","/var/www/EC-ElGamal/GenPerm.sh", str(n), str(total)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
	    output,err = p.communicate()
	    votes[ab] = output
	    #read from the disk file for ciphers
	    f = open('/var/www/EC-ElGamal/EC_cipher.txt')
	    lines = f.readlines()
	    f.close()
	    i = 0
	    for enc in lines:
		i+=1
		if i >= 2:
		    if i%2 == 0:
			ciphers[ab]+=" "
		    else: #" " and "," alternating
			ciphers[ab]+=","	
		ciphers[ab]+=enc.strip()
	    #read from the disk file for plains
            f = open('/var/www/EC-ElGamal/EC_plain.txt')
            lines = f.readlines()
            f.close()
            i = 0
            for decommit in lines:
		if i == 0:
		    plains[ab]+=decommit.strip()
		if i == 1:
		    decom[ab]+=decommit.strip()
		if i>0 and i%2 == 0:
		    plains[ab]+=","
		    plains[ab]+=decommit.strip()
		if i%2 == 1 and i>1:
		    decom[ab]+=","
		    decom[ab]+=decommit.strip()
                i+=1

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
	new_b = Ballot(election = e, serial = serial, key = skey, votes1 = votes[0],votes2 = votes[1],plain1 = plains[0],plain2 = plains[1], decom1 = decom[0], decom2 = decom[1] ,cipher1 = ciphers[0],cipher2 = ciphers[1], codes1 = codes[0],codes2 = codes[1],rec1 = recs[0],rec2 = recs[1])
        new_b.save()
    #mark as prepared
    e.prepared = True
    e.save()
    # assign email ballots
    #get choices
    options = e.choice_set.order_by('id').values('text')
    opts = [x['text'] for x in options]
    #get all the unassigned ballots
    unused = Ballot.objects.filter(election = e)# all are not used
    counter = 0
    for voter in emails:
	#generate random token
	token = long(binascii.hexlify(os.urandom(KSIZE)), 16)
        stoken = base36encode(token)#no padding 128 bit
	b = unused[counter]
	counter += 1
	email = voter.strip()
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
##################################String sort bug!!!!!!!!!!!!#######################
    	perm1 = [int(x) for x in b.votes1.split(',')]
    	perm2 = [int(x) for x in b.votes2.split(',')]
####################################################################################
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
	for i in range(n):
	    emailbody+= "Votecode: "+ballot_code1[i]+"  Receipt: "+ballot_rec1[i]+ "  Option: "+opts[i]+"\n"
        emailbody+= "================================================\nBallot B: \n"
        for i in range(n):
            emailbody+= "Votecode: "+ballot_code2[i]+"  Receipt: "+ballot_rec2[i]+ "  Option: "+opts[i]+"\n"
	emailbody+= "================================================\n"
    	emailbody+= "\nVBB url: "+BB_URL+"vbb/"+e.EID+"/\n"
    	emailbody+= "ABB url: "+BB_URL+"abb/"+e.EID+"/\n"
	emailbody+= "Client url: "+CLIENT_URL+e.EID+"/"+stoken+"/\n"
    	emailbody+= "\nFINER Ballot Distribution Server\n"
    	#send email		
    	p = subprocess.Popen(["sudo","/var/www/finer/bingmail.sh","Ballot for Election No. "+e.EID, emailbody,email],stdout=subprocess.PIPE,stderr=subprocess.PIPE, env=env)
    	output,err = p.communicate()
###################
#pdf ballots
    zip_buffer = cStringIO.StringIO()
    zfile = zipfile.ZipFile(zip_buffer,'w')
    for i in range(intpdf):
	#generate random token
	token = long(binascii.hexlify(os.urandom(KSIZE)), 16)
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
##################################String sort bug!!!!!!!!!!!!#######################
        perm1 = [int(x) for x in b.votes1.split(',')]
        perm2 = [int(x) for x in b.votes2.split(',')]
####################################################################################
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
	#create pdf doc
	doc = SimpleDocTemplate(buffer, pagesize=A4,leftMargin=0.1*inch,rightMargin=0.1*inch)
	style = ParagraphStyle(
        	name='Normal',
		#firstLineIndent = 0,
		#leftIndent = 0,
        	fontName='LiberationSansBd',
        	fontSize=14,
		leftMargin=0.3*inch,
            	firstLineIndent = 0.3*inch,
    	)
    
    	style_warning = ParagraphStyle(
        	name='Normal',
        	fontName='LiberationSans',
        	fontSize=12,
        	leftMargin=0.3*inch,
                firstLineIndent = 0.3*inch,
    	)
	#prepare table data
	data = [['Options', 'Votecode A', 'Receipt A']]
	data2 = [['Options', 'Votecode B', 'Receipt B']]

	for ii in range(n):
		data.append([opts[ii],ballot_code1[ii], ballot_rec1[ii]])
                data2.append([opts[ii],ballot_code2[ii], ballot_rec2[ii]])

	#pdf part
	parts = []
	parts.append(Paragraph("Serial Number: "+b.serial,style_warning))
    	parts.append(Spacer(1, 0.2 * inch))
    	table_with_style = Table(data, [5.2 * inch, 1.3 * inch, 0.8*inch])

   	table_with_style.setStyle(TableStyle([
    	('FONT', (0, 0), (-1, -1), 'LiberationSans'),
    	('FONT', (0, 0), (-1, 0), 'LiberationSansBd'),
    	('FONTSIZE', (0, 0), (-1, -1), 9),
    	('INNERGRID', (0, 0), (-1, -1), 0.25, colors.black),
    	('BOX', (0, 0), (-1, 0), 0.25, colors.green),
    	('ALIGN', (0, 0), (-1, 0), 'CENTER'),
    	('BOX',(0,0),(-1,-1),2,colors.black),
    	]))
    
    	parts.append(table_with_style)

    	parts.append(Spacer(1, 0.1 * inch))

    	table_with_style = Table(data2, [5.2 * inch, 1.3 * inch, 0.8*inch])

    	table_with_style.setStyle(TableStyle([
    	('FONT', (0, 0), (-1, -1), 'LiberationSans'),
    	('FONT', (0, 0), (-1, 0), 'LiberationSansBd'),
    	('FONTSIZE', (0, 0), (-1, -1), 9),
    	('INNERGRID', (0, 0), (-1, -1), 0.25, colors.black),
    	('BOX', (0, 0), (-1, 0), 0.25, colors.green),
    	('ALIGN', (0, 0), (-1, 0), 'CENTER'),
    	('BOX',(0,0),(-1,-1),2,colors.black),
    	]))
    
    	parts.append(table_with_style)

    	parts.append(Spacer(1, 0.4 * inch))
	parts.append(Paragraph("VBB URL: "+BB_URL+"vbb/"+e.EID+"/",style_warning))
        parts.append(Paragraph("ABB URL: "+BB_URL+"abb/"+e.EID+"/",style_warning))
	parts.append(Paragraph("CLIENT: "+CLIENT_URL+e.EID+"/"+stoken+"/",style_warning))
        parts.append(Spacer(1, 0.4 * inch))
    	parts.append(Paragraph("DEMOS Ballot Distribution Center", style))
    	doc.build(parts)

	#save pdf
        zfile.writestr("Ballots/"+str(i)+".pdf", buffer.getvalue())
        buffer.close()

    if intpdf > 0:#if there is at least one pdf ballot
	#generate random token
    	token = long(binascii.hexlify(os.urandom(16)), 16)
    	stoken = base36encode(token)#no padding 128 bit
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
    	p = subprocess.Popen(["sudo","/var/www/finer/bingmail.sh","PDF Ballots for Election No. "+e.EID, emailbody,e.c_email],stdout=subprocess.PIPE,stderr=subprocess.PIPE, env=env)
    	output,err = p.communicate()	

########################################
	
###generate and send keys to key holders
    keyholders = keyemails.split(',')
    key_shares = []
    for email in keyholders:
	k1 = os.urandom(KSIZE)
	key_shares.append(k1)
    	sk1 = base64.b64encode(k1)
	salt = os.urandom(KSIZE)
	#base36 for url
        ss = base36encode(long(binascii.hexlify(salt), 16))#no padding 128 bit
	h = hashlib.sha256(sk1+ss)
	sh = base64.b64encode(h.digest())
	kh = Keyholder(election = e, email = email, key = sk1,hash = sh, salt = ss)
	kh.save()	
    	emailbody = "Dear Key Holder,\n\n Your private key is:\n"
    	emailbody+= "================================================\n"	
    	emailbody+= sk1+"\n"
    	emailbody+= "================================================\n"
    	emailbody+= "\nYour Tally URL: "+BB_URL+"keyholder/"+e.EID+"/"+ss+"\n"
    	emailbody+= "\nFINER  Election Authority\n"
    	#send email         
    	p = subprocess.Popen(["sudo","/var/www/finer/bingmail.sh","Private Key for Election No. "+e.EID, emailbody,email.strip()],stdout=subprocess.PIPE,stderr=subprocess.PIPE, env=env)
    	output,err = p.communicate()
##########################
    #send ABB CSV data
    #random key for column 1
    k1 = os.urandom(KSIZE)
    sk1 = base64.b64encode(k1)
    #create csv file and encrypt the codes
    output = cStringIO.StringIO() ## temp output file
    writer = csv.writer(output, dialect='excel')
    #first row n, k1.
    writer.writerow([str(n),sk1])
    #key holders' info
    all_keyholders = e.keyholder_set.all()
    for kholder in all_keyholders:
	writer.writerow([kholder.email,kholder.hash,kholder.salt])
    #get all the ballots
    all_ballots = Ballot.objects.filter(election = e)
    for each in all_ballots:
	writer.writerow([each.serial,each.key])#second row serial , key.
	#encrypt codes
	temp_list = each.codes1.split(',')
	enc_list = []#clear enc_list
	for temp in temp_list:
	    enc_list.append(base64.b64encode(encrypt(temp,k1,key_size=128)))	
	writer.writerow(enc_list)
	#write cipher
	temp_list = each.cipher1.split(',')
	writer.writerow(temp_list)
	#write plain
        temp_list = each.plain1.split(',')
	enc_list = []
	# add key_shares
	opt_counter = 0
	for temp in temp_list:
	    sum = long(base64.b64decode(temp).encode('hex'),16)
	    for ks in key_shares:
		message1 = each.serial+"a"+str(opt_counter)+"m0"
		message2 = each.serial+"a"+str(opt_counter)+"m1"
		#2* 256 = 512
		c1 = hmac.new(ks,message1, digestmod=hashlib.sha256).digest()
		c2 = hmac.new(ks,message2, digestmod=hashlib.sha256).digest()
		c12 = c1+c2
                lc = long(binascii.hexlify(c12), 16) #convert to long
		sum += lc
	    enc_list.append(base64.b64encode(long_to_bytes(sum))) 
	    opt_counter+=1
        writer.writerow(enc_list)
	#write decom
	temp_list = each.decom1.split(',')
        enc_list = []
        # add key_shares
        opt_counter = 0
        for temp in temp_list:
            sum = long(base64.b64decode(temp).encode('hex'),16)
            for ks in key_shares:
                message1 = each.serial+"a"+str(opt_counter)+"r0"
                message2 = each.serial+"a"+str(opt_counter)+"r1"
                #2* 256 = 512
                c1 = hmac.new(ks,message1, digestmod=hashlib.sha256).digest()
                c2 = hmac.new(ks,message2, digestmod=hashlib.sha256).digest()
                c12 = c1+c2
                lc = long(binascii.hexlify(c12), 16) #convert to long
                sum += lc
            enc_list.append(base64.b64encode(long_to_bytes(sum)))
            opt_counter+=1
        writer.writerow(enc_list)
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
        #write plain
        temp_list = each.plain2.split(',')
        enc_list = []#clear enc_list
        # add key_shares
        opt_counter = 0
        for temp in temp_list:
            sum = long(base64.b64decode(temp).encode('hex'),16)
            for ks in key_shares:
                message1 = each.serial+"b"+str(opt_counter)+"m0"
                message2 = each.serial+"b"+str(opt_counter)+"m1"
                #2* 256 = 512
                c1 = hmac.new(ks,message1, digestmod=hashlib.sha256).digest()
                c2 = hmac.new(ks,message2, digestmod=hashlib.sha256).digest()
                c12 = c1+c2
                lc = long(binascii.hexlify(c12), 16) #convert to long
                sum += lc
            enc_list.append(base64.b64encode(long_to_bytes(sum)))
            opt_counter+=1
        writer.writerow(enc_list)
	#write decom2
        temp_list = each.decom2.split(',')
        enc_list = []
        # add key_shares
        opt_counter = 0
        for temp in temp_list:
            sum = long(base64.b64decode(temp).encode('hex'),16)
            for ks in key_shares:
                message1 = each.serial+"b"+str(opt_counter)+"r0"
                message2 = each.serial+"b"+str(opt_counter)+"r1"
                #2* 256 = 512
                c1 = hmac.new(ks,message1, digestmod=hashlib.sha256).digest()
                c2 = hmac.new(ks,message2, digestmod=hashlib.sha256).digest()
                c12 = c1+c2
                lc = long(binascii.hexlify(c12), 16) #convert to long
                sum += lc
            enc_list.append(base64.b64encode(long_to_bytes(sum)))
            opt_counter+=1
        writer.writerow(enc_list)
    #post
    reply = requests.post(BB_URL+'abb/'+e.EID+'/upload/',files = {'inputfile':ContentFile(output.getvalue(),name = "init.csv")}, verify=False)
    #close
    output.close()
    return reply






