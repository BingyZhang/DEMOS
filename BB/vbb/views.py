# -*- coding: utf-8 -*-
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render_to_response, render
from django.http import HttpResponse, HttpResponseRedirect
from django.template import RequestContext
from vbb.forms import VoteForm, FeedbackForm
from vbb.models import Vbb, Dballot, Election, Choice, Bba
from abb.models import UpdateInfo,Abbinit, Auxiliary
from django.utils import timezone
import datetime, cStringIO, zipfile, csv, copy,os, base64, random,hmac,hashlib,binascii,subprocess, qrcode,codecs
from django.core.files import File
from reportlab.lib.utils import ImageReader
from reportlab.pdfgen import canvas
from reportlab.pdfbase import pdfmetrics 
from reportlab.pdfbase.ttfonts import TTFont
from decimal import *
# Create your views here.
magic_X = 700



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


def empty(request):
	return HttpResponse('Please specify the election ID.')

def tally(e):
	#cancel all the key streams
	plain = []
	keys = e.keyholder_set.all()
	for k in keys:
		plain+=k.keystream.split(",")
	aux = e.auxiliary_set.all()[0]
        temp_c = aux.tallycipher.split(",")
	temp_list = []
	for temp in temp_c:
		temp_list.append(temp.strip())#remove \n, because ..
	temp_str_c = "\n".join(temp_list)#already has \n due to lines
        plain.append(aux.tallyplain)
	plain.append(aux.tallydecom)
        temp_str_d = "\n".join(plain)
	p = subprocess.Popen(["sh","/var/www/finer/EC-ElGamal/Tally.sh",temp_str_c, temp_str_d],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        output,err = p.communicate()
	if int(output) == 1:
        	aux.verify = True
        f = open('/var/www/finer/EC-ElGamal/EC_decommit.txt')
        lines = f.readlines()
        f.close()
        aux.tallyplain = lines[0]
        aux.tallydecom = lines[1]
        aux.save()
	

       #compute and store result
	opts = e.choice_set.order_by('id')
	n = len(opts)
        tallyresult = 0
        T = long(base64.b64decode(lines[0]).encode('hex'),16)
        max = e.total
        for i in range(n):
                tallyresult = T%max
                T = (T - tallyresult)/max
                opts[i].votes = tallyresult
                opts[i].save()
	return 0




def send_request(e):
	#tally
	tallyset = []
	votes = e.vbb_set.all()
	#if nobody voted directly return
	if len(votes)==0:
		e.tally = True
        	e.save()
		aux = Auxiliary(election = e,verify = True, tallyplain = "No Vote", tallycipher = "0")
		aux.save()
		return 0
	opts = e.choice_set.order_by('id')
	n = len(opts)
	#get all for fast disk IO
	abbs = e.abbinit_set.all()
	opt_ciphers = []#ElGamal
	opt_plains = []#decommit
        #prepare the table_data
        for each in votes:
		feedback = each.dballot_set.filter(checked = True)
                record = abbs.get(serial = each.serial)
		codes1 = record.codes1.split(',')
		codes2 = record.codes2.split(',')
		cipher1 =record.cipher1.split(',')
		cipher2 = record.cipher2.split(',')
		plain1 = record.plain1.split(',')
		plain2 = record.plain2.split(',')
		decom1 = record.decom1.split(',')
                decom2 = record.decom2.split(',')
		mark1 = []
		mark2 = []
		for i in range(n):
			if each.votecode == codes1[i]:
				mark1.append("Voted")
				#add tally set
				tallyset.append(each.serial+"a"+str(i))
				# put ciphers
				temp = cipher1[2*i].split(' ')
				for t in temp:
					opt_ciphers.append(t)
                                temp = cipher1[2*i+1].split(' ')
                                for t in temp:
                                        opt_ciphers.append(t)
				#plain and decommit
				opt_plains.append(plain1[i])
				opt_plains.append(decom1[i])
			else:
				mark1.append("")
		for i in range(n):
                        if each.votecode == codes2[i]:
                                mark2.append("Voted")
                                #add tally set
                                tallyset.append(each.serial+"b"+str(i))
                                # put ciphers
                                temp = cipher2[2*i].split(' ')
                                for t in temp:
                                        opt_ciphers.append(t)
                                temp = cipher2[2*i+1].split(' ')
                                for t in temp:
                                        opt_ciphers.append(t)
                                #plain and decommit
                                opt_plains.append(plain2[i])
                                opt_plains.append(decom2[i])
                        else:
                                mark2.append("")
		#mark feedbacks
                if len(feedback)!=0:
			for feed in feedback:
				for i in range(n):
                        		if feed.code == codes1[i]:
						mark1[i] = feed.value
				for i in range(n):
                                        if feed.code == codes2[i]:
                                                mark2[i] = feed.value
		#store marks
		record.mark1 = ",".join(mark1)
		record.mark2 = ",".join(mark2)
		record.save()
	#output for tally
	temp_str_c = "\n".join(opt_ciphers)
	temp_str_d = "\n".join(opt_plains)
	p = subprocess.Popen(["sh","/var/www/finer/EC-ElGamal/Tally.sh",temp_str_c, temp_str_d],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
	output,err = p.communicate()
	#read the files and create Aux
	aux = Auxiliary(election = e)
	f = open('/var/www/finer/EC-ElGamal/EC_sum.txt')
        lines = f.readlines()
        f.close()
	aux.tallycipher = ",".join(lines)	

        f = open('/var/www/finer/EC-ElGamal/EC_decommit.txt')
        lines = f.readlines()
        f.close()
        aux.tallyplain = lines[0].strip()
	aux.tallydecom = lines[1].strip()
	aux.save()	
	#save tally set and mark tally flag
	e.tally = True
	e.tallySet = ",".join(tallyset)
	e.save()
    	return 1

def verify_code(e,s,vcode):
	codelist = []
	templist = []
	receipt = ""
	try:
		record = e.bba_set.get(serial = s)
	except Bba.DoesNotExist:
		return codelist,receipt
	if record.voted:
		return codelist,receipt
	checkcode = removebars(vcode)
        key = base64.b64decode(record.key)
        n = record.n
        #check hmac
        codes1 = []
        codes2 = []
        rec1 = []
        rec2 = []
	#return codelist,str(n)
        for i in range(n):
                message = bytes(s+str(0)+str(i)).encode('utf-8') 
                c = hmac.new(key, message, digestmod=hashlib.sha256).digest()
	        c1 = long(binascii.hexlify(c[0:8]), 16) #convert 64 bit string to long
	        c1 &= 0x3fffffffffffffff # 64 --> 62 bits
		sc1 = base36encode(c1)
                while len(sc1)<12:#length padding
                    sc1 = "0"+sc1
	        codes1.append(sc1)
	        r1 = long(binascii.hexlify(c[8:12]), 16) #convert 32 bit string to long
                r1 &= 0x7fffffff # 32 --> 31 bits
		sr1 = base36encode(r1)
                while len(sr1)<6:#length padding
                    sr1 = "0"+sr1
                rec1.append(sr1)
                #ballot 2
                message = bytes(s+str(1)+str(i)).encode('utf-8') 
                c = hmac.new(key, message, digestmod=hashlib.sha256).digest()
	        c2 = long(binascii.hexlify(c[0:8]), 16) #convert 64 bit string to long
	        c2 &= 0x3fffffffffffffff # 64 --> 62 bits
		sc2 = base36encode(c2)
                while len(sc2)<12:#length padding
                    sc2 = "0"+sc2
	        codes2.append(sc2)
	        r2 = long(binascii.hexlify(c[8:12]), 16) #convert 32 bit string to long
                r2 &= 0x7fffffff # 32 --> 31 bits
		sr2 = base36encode(r2)
                while len(sr2)<6:#length padding
                    sr2 = "0"+sr2
                rec2.append(sr2)
	for i in range(n):
                if codes1[i] == checkcode:
                        templist = codes2
                        receipt = rec1[i]
                        record.voted = True
                        record.save()
                        break
                if codes2[i] == checkcode:
                        templist = codes1
                        receipt = rec2[i]
                        record.voted = True
                        record.save()
                        break
	for x in templist:
		codelist.append(addbars(x))  #add bars     
	return codelist,receipt



def index(request, eid = 0):
	try:
		e = Election.objects.get(EID=eid)
	except Election.DoesNotExist:
		return HttpResponse('The election ID is invalid!')
	time = 0
	options = e.choice_set.all()
	#short party names only sorted
	short_opts = [[x.votes, x.text.split(";")[0]] for x in options ]
	sorted_opts = sorted(short_opts,reverse=True)
	table_data = []
	checkcode = "invalid code"
	running = 0
	if e.was_started():
		running = 1
		time = int((e.end - timezone.now()).total_seconds())
	if e.was_ended():
		running = 2
		if not e.request:
			send_request(e)
			e.request = True
			e.save()
			pass
		else:
			if e.tally and e.keys == e.keysTotal:
				running = 3
	#if e.pause:
        #        running = 10
	if request.method == 'POST':#there are two posts
		if running != 1:
			return HttpResponse("invalid code")
		if request.is_ajax():#ajax post
			form = VoteForm(request.POST) # A form bound to the POST data
			if form.is_valid(): # All validation rules pass
				s = form.cleaned_data.get('serial').upper()#request.POST['serial']
				c = form.cleaned_data.get('code').upper()#request.POST['code']
				if len(s) == 0 or len(c) ==0:
					return HttpResponse("invalid code")
				codelist,receipt = verify_code(e,s,c)
				if receipt != "":
					#add the code to DB
					new_entry = Vbb(election = e, serial = s, votecode = c)
					new_entry.save()
					#store the dual ballot
					for i in range(len(codelist)):
						balls = Dballot(vbb = new_entry, serial = s, code = codelist[i])
						balls.save()
					#return HttpResponse(receipt)
                                        return render_to_response('feedback.html', {'codes': codelist,'options':short_opts,'rec':receipt}, context_instance=RequestContext(request))
                                else:
                                        return HttpResponse("invalid code")
			else:
				return HttpResponse("invalid code")
		else:
			form = FeedbackForm(request.POST) # A form bound to the POST data
			if form.is_valid(): # All validation rules pass
				ic = form.cleaned_data.get('checkcode')				
				io = form.cleaned_data.get('checkoption') #request.POST['checkoption']
				if "Select" not in io and "Select" not in ic:# good feedback
                                        ball = Dballot.objects.get(code = ic)
                                        ball.value = io
					ball.checked = True
                                        ball.save()
				return render_to_response('thanks.html')
			else:
				return HttpResponse("Wrong Form")
	else:# no post
		data = e.vbb_set.all().order_by('-date')
		#prepare the table_data
		for item in data:
			temp_row = []
			temp_row.append(item.serial)
			temp_row.append(item.votecode)
			temp_row.append(item.date)
			unused = item.dballot_set.filter(checked = True)
			l = len(unused)
			if l==0:
			    temp_row.append("")
			    temp_row.append("")			

			else:
			#randomly display one
			    if l > 1:
				x = random.randrange(l)
				temp_row.append(unused[x].code)
                                temp_row.append(unused[x].value)
			    else: 
                                temp_row.append(unused[0].code)
			        temp_row.append(unused[0].value)
			table_data.append(temp_row)
		progress = int(e.vbb_set.count()*100/e.total+0.5)

		return render_to_response('vbb.html', {'data':table_data, 'options':sorted_opts, 'time':time, 'running':running, 'election':e, 'progress':progress}, context_instance=RequestContext(request))


def export(request, eid = 0):
        try:
		e = Election.objects.get(EID=eid)
	except Election.DoesNotExist:
		return HttpResponse('The election ID is invalid!')
	response = HttpResponse(content_type="application/zip")  
        response['Content-Disposition'] = 'attachment; filename=VBB['+timezone.now().strftime('%B-%d-%Y')+'].zip'
        z = zipfile.ZipFile(response,'w')   ## write zip to response
	#export serial numbers and voted codes 
        data = e.vbb_set.all()
        output = cStringIO.StringIO() ## temp CSV file
        writerA = csv.writer(output, dialect='excel')       
        for item in data:
                writerA.writerow([item.serial,timezone.localtime(item.date).strftime('%B-%d-%Y %H:%M:%S'), item.votecode])
        z.writestr("Votes.csv", output.getvalue())  ## write votes csv file to zip
        return response


@csrf_exempt
def client(request, eid = 0):
    try:
	e = Election.objects.get(EID=eid)
    except Election.DoesNotExist:
	return HttpResponse('The election ID is invalid!')
    if request.method == 'POST':
	if request.is_ajax():#ajax post
	    #check election is running?
	    running = 0
	    if e.was_started():
		running = 1
	    if e.was_ended():
		running = 2
		if not e.request:
		    send_request(e)
		    e.request = True
		    e.save()
		    pass
	    #if e.pause:
		#running = 10
	    if running != 1:
		return HttpResponse("invalid code")
	    feedback = []
            # maximum 50 options
            for i in range(1,51):
                temp = request.POST.get('feedback'+str(i),'')
                if temp != '':
                    feedback.append(temp)
                else:
                    break
            code = request.POST["code"].upper()
            serial = request.POST["serial"].upper()
            codelist,receipt = verify_code(e,serial,code)
            if receipt != "":
                #add the code to DB
                new_entry = Vbb(election = e, serial = serial, votecode = code)
                new_entry.save()
                #store the dual ballot feedback
                for x in feedback:
                    feed = x.split(",")
                    if feed[0] in codelist:
                        balls = Dballot(vbb = new_entry, serial = serial, code = feed[0], checked = True, value = feed[1])
                        balls.save()
                return HttpResponse(receipt)
            else:
                return HttpResponse('invalid code')
	#404 if not ajax for security
	return render_to_response('404.html')        
    else:
        return render_to_response('404.html')








@csrf_exempt
def upload(request, eid = 0):
    try:
	e = Election.objects.get(EID=eid)
    except Election.DoesNotExist:
	return HttpResponse('The election ID is invalid!')
    if request.method == 'POST':
        zfile = request.FILES['inputfile']
        sig = request.FILES['sig']
        ## Sanity checks...

        #processing upload files
	z = zipfile.ZipFile(zfile, 'r')
	for name in z.namelist():
                if name.endswith(".txt"):
			opfile = z.read(name)
		else:
			datafile = z.read(name)
        ## Record update log
	notes = timezone.now().isoformat(' ')+"-"+opfile
	zfile.name = notes+".zip"
	sig.name = "Sig_"+notes+".txt"
        new_op = UpdateInfo(election = e, text = notes, file = zfile, sig = sig)
        new_op.save()
        flag = 0
        if opfile == 'votecode':
                flag = 1 
                reader = datafile.splitlines()
                #populate BBA database handle CSV file myself
                for rows in reader:
                        if rows != '':
                                items = rows.split(',')
                                new_entry = Bba(election = e, serial = items[0].strip().upper(), code = items[1].strip().upper())
                                new_entry.save()
                return HttpResponse('The votecodes have been uploaded to VBB.')                
        elif opfile == 'end':
                flag = 1 
                e.end = timezone.now()
                e.save()
                return HttpResponse('The election is ended.')
        elif opfile == 'lock':
                flag = 1 
                e.pause = True
                e.save()
                return HttpResponse('The election is locked.')
        elif opfile == 'unlock':
                flag = 1 
                e.pause = False
                e.save()
                return HttpResponse('The election is unlocked.')
        if flag == 1:
            return HttpResponse('The data has been uploaded to VBB.')
        else:
            return HttpResponse('Sorry, the operation code is not recognized.')                
        
        
    else:
        return render_to_response('404.html')




def keyholder(request, eid = 0,salt = ""):
	try:
		e = Election.objects.get(EID=eid)
	except Election.DoesNotExist:
		return HttpResponse('The election ID is invalid!')
	kh = e.keyholder_set.filter(salt = salt)
	if len(kh) ==0:
		return HttpResponse('The hash digest is invalid!')
	holder = kh[0]
	if holder.opened:
		return HttpResponse('You have already submitted your key!')
	if request.method == 'POST':#there are two posts
		keyR = request.POST["keyR"].strip()
		keyM = request.POST["keyM"].strip()
		hash = request.POST["hash"].strip()
		if not hash == holder.hash:
			return HttpResponse('The key is incorrect!')
		#save the random key stream.
		holder.keystream = keyM+","+keyR
		holder.opened = True
		holder.save()
		#add key counter
		e.keys = e.keys+1
		e.save()
		#if all key holders, do tally
		if e.keys == e.keysTotal:
			tally(e)		
		return HttpResponse("Success!")
	else:
		if e.was_ended():
                        if not e.request:
                                send_request(e)
                                e.request = True
                                e.save()             
			return render_to_response('keyholder.html',{'tallyset':e.tallySet.split(","),'salt':salt},context_instance=RequestContext(request))
		else:
			return HttpResponse('The election is not ended yet! Please come back later')

def test(request, eid = 0):
    try:
	e = Election.objects.get(EID=eid)
    except Election.DoesNotExist:
	return HttpResponse('The election ID is invalid!')
    votes = e.vbb_set.all()
    abbs = e.abbinit_set.all()
    opts = e.choice_set.order_by('id')
    n = len(opts)
    A = 0
    B = 0
    for each in votes:
	record = abbs.get(serial = each.serial)
	codes1 = record.codes1.split(',')
	codes2 = record.codes2.split(',')
	for i in range(n):
		if each.votecode == codes1[i]:
			A+=1
		if each.votecode == codes2[i]:
			B+=1
    C = A+B
    
    return HttpResponse('A: '+str(Decimal(A)/C)+"% B: "+str(Decimal(B)/C)+"%")



def thanks(request):
    return render_to_response('thanks.html')
