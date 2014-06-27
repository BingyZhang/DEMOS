from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render_to_response, render
from django.http import HttpResponse, HttpResponseRedirect
from django.core.paginator import Paginator, InvalidPage
from crypto import commitment
import time, requests, hashlib
from datetime import datetime
from django.template import RequestContext
from vbb.models import Election,Choice,Randomstate,Bba,Keyholder
from Crypto.Cipher import AES
from Crypto import Random
from django.utils import timezone
from abb.models import AbbKey,AbbData, UpdateInfo, Auxiliary,Abbinit
import cStringIO, zipfile, csv, copy,os, base64, random
from django.core.files import File
from decimal import *

# Create your views here.

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




#used to create tabs in html template
class Ctuple:
    def __init__(self, o, x,y,z):
        self.opened = o
        self.plaintext = str(x)
        self.commitment = str(y)
        self.decommitment = str(z)

class DataTriple:
    def __init__(self, x,y,z):
        self.Data = x
        self.Ver = y
        self.Log = z

col_names = ['Serial #', 'Vote Code', 'Candidate Index', 'Pre-vote Audit', 'Vote & Feedback Mark','Random Coin', 'Post-vote Audit']

col_mapping = {'SN&VC (comm)':1,	 'SN&VC (plain)':2,	 'SN&VC (decomm)':3,	 'PCheck (comm)':4,	 'PCheck (plain)':5,	 'PCheck (decomm)':6,	 'PossVote (comm)':7,	 'PossVote (plain)':8,	 'PossVote (decomm)':9,	 'MarkVoted (comm)':10,	 'MarkVoted (plain)':11,	 'MarkVoted (decomm)':12,	 'PreSumA (comm)':13,	 'PreSumA (plain)':14,	 'PreSumA (decomm)':15,	 'PreSumB (comm)':16,	 'PreSumB (plain)':17,	 'PreSumB (decomm)':18,	 'FinalSumA (comm)':19,	 'FinalSumA (plain)':20,	 'FinalSumA (decomm)':21,	 'FinalSumB (comm)':22,	 'FinalSumB (plain)':23,	 'FinalSumB (decomm)':24}
 
col_full_names = ['SN&VC (comm)',	 'SN&VC (plain)',	 'SN&VC (decomm)',	 'PCheck (comm)',	 'PCheck (plain)',	 'PCheck (decomm)',	 'PossVote (comm)',	 'PossVote (plain)',	 'PossVote (decomm)',	 'MarkVoted (comm)',	 'MarkVoted (plain)',	 'MarkVoted (decomm)',	 'PreSumA (comm)',	 'PreSumA (plain)',	 'PreSumA (decomm)',	 'PreSumB (comm)',	 'PreSumB (plain)',	 'PreSumB (decomm)',	 'FinalSumA (comm)',	 'FinalSumA (plain)',	 'FinalSumA (decomm)',	 'FinalSumB (comm)',	 'FinalSumB (plain)',	 'FinalSumB (decomm)']

def empty(request):
	return HttpResponse('Please specify the election ID.')





def index(request, eid = 0, tab = -1):
    try:
	e = Election.objects.get(EID=eid)
    except Election.DoesNotExist:
	return HttpResponse('The election ID is invalid!')
    #if not ready
    if not e.prepared:
        return HttpResponse('Not ready yet!')
#display results 
    options = e.choice_set.all()
    short_opts = []
    sorted_opts = []
    #short party names only sorted
    short_opts = [[x.votes, x.text] for x in options ]
    sorted_opts = sorted(short_opts,reverse=True)

    abb_list = e.abbinit_set.all()
    p = Paginator(abb_list,1)

    if request.method == 'POST':
	try:
	    check_serial = int(request.POST.get('serial','100'))
	except ValueError:
	    check_serial = 100#first one
	page = check_serial-99

	if page > e.total:
	    page = 1
	current = p.page(page)
    else:
        page = 1
        current = p.page(page)
    if current.has_next():
        next_page = page+1
    else:
        next_page = 0    
    int_tab = int(tab)
    #version 1 or 1,2
    version = [1]
    finaltally = None
    resultshow = False
    if e.tally:
	if e.keys == e.keysTotal:
	    resultshow = True
	if int_tab == -1:
	    int_tab = 2
        version.append(2)
	auxset = e.auxiliary_set.all()
	finaltally = auxset[0]
    else:
	if int_tab == -1:
            int_tab = 1
    Vtable = []
    #version 1
    if int_tab == 1:
        table = []
        for entry in current.object_list:	
            enc1 = entry.enc1.split(',')
            enc2 = entry.enc1.split(',')
            elen = len(enc1)
            cipher1 = entry.cipher1.split(',')
            clen = len(cipher1)
            rowlen = clen/elen
            cipher2 = entry.cipher2.split(',')
            #fake aux column
            ZKone1 = entry.ZKone1.split(',')
            ZKone2 = entry.ZKone2.split(',')
            zeroone = entry.zeroone
            for i in range(elen):
                if i ==0:
                    s = entry.serial+" A"
                else:
                    s = ''
                temp = ",".join(cipher1[rowlen*i:rowlen*(i+1)])    
                table.append([{'bit':zeroone,'serial':s},{'enc':enc1[i],'code':""},{'cipher':temp},{'aux':ZKone1[i]},{'mark':""},{'rand':""},{}])
            for i in range(elen):
                if i ==0:
                    s = entry.serial+" B"
                else:
                    s = ''
                temp = ",".join(cipher1[rowlen*i:rowlen*(i+1)])     
                table.append([{'bit':zeroone,'serial':s},{'enc':enc2[i],'code':""},{'cipher':temp},{'aux':ZKone2[i]},{'mark':""},{'rand':""},{}])
        Vtable.append(table)
    if int_tab == 2:# ver. 2
	table = []
        for entry in current.object_list:
        	enc1 = entry.enc1.split(',')
            	enc2 = entry.enc1.split(',')
            	elen = len(enc1)
            	cipher1 = entry.cipher1.split(',')
            	clen = len(cipher1)
            	rowlen = clen/elen
            	cipher2 = entry.cipher2.split(',')
            	#fake aux column
            	ZKone1 = entry.ZKone1.split(',')
            	ZKone2 = entry.ZKone2.split(',')
		rand1 = entry.rand1.split(',')
		rand2 = entry.rand2.split(',')
		code1 = entry.codes1.split(',')
                code2 = entry.codes2.split(',')
		if entry.mark1:
		    mark1 = entry.mark1.split(',')
		else:
		    mark1 = [""]*elen
		if entry.mark2:
		    mark2 = entry.mark2.split(',')
		else:
                    mark2 = [""]*elen
            	zeroone = entry.zeroone
            	for i in range(elen):
                    if i ==0:
                    	s = entry.serial+" A"
                    else:
                    	s = ''
                    temp = ",".join(cipher1[rowlen*i:rowlen*(i+1)])
                    table.append([{'bit':zeroone,'serial':s},{'enc':enc1[i],'code':code1[i]},{'cipher':temp},{'aux':ZKone1[i]},{'mark':mark1[i]},{'rand':rand1[i]},{'post':enc1[i][5:]}])
                for i in range(elen):
                    if i ==0:
                        s = entry.serial+" B"
                    else:
                        s = ''
                    temp = ",".join(cipher1[rowlen*i:rowlen*(i+1)])
                    table.append([{'bit':zeroone,'serial':s},{'enc':enc2[i],'code':code2[i]},{'cipher':temp},{'aux':ZKone2[i]},{'mark':mark2[i]},{'rand':rand2[i]},{'post':enc1[i][5:]}])
        Vtable.append(table)
    #end of verion 2
    BigData={'Data':Vtable,'Ver':version} 
    return render_to_response('abb.html', {'election':e,'tab':int_tab, 'options':sorted_opts, 'resultshow': resultshow, 'final':finaltally, 'next_page':next_page, 'BigData':BigData, 'col_names':col_names},  context_instance=RequestContext(request))         
     


def scroll(request, eid = 0, tab = 1, page = 1):
    try:
        e = Election.objects.get(EID=eid)
    except Election.DoesNotExist:
        return HttpResponse('The election ID is invalid!')
    Vtable = []
    #if not ready
    if not e.prepared:
        return HttpResponse('Not ready yet!')
    abb_list = e.abbinit_set.all()
    p = Paginator(abb_list,1)
    int_page = int(page)
    current = p.page(int_page)
    if current.has_next():
        next_page = int_page+1
    else:
        next_page = 0
    int_tab = int(tab)    
    #version 1
    if int_tab == 1:
        table = []
        for entry in current.object_list:	
            enc1 = entry.enc1.split(',')
            enc2 = entry.enc1.split(',')
            elen = len(enc1)
            cipher1 = entry.cipher1.split(',')
            clen = len(cipher1)
            rowlen = clen/elen
            cipher2 = entry.cipher2.split(',')
            #fake aux column
            ZKone1 = entry.ZKone1.split(',')
            ZKone2 = entry.ZKone2.split(',')
            zeroone = entry.zeroone
            for i in range(elen):
                if i ==0:
                    s = entry.serial+" A"
                else:
                    s = ''
                temp = ",".join(cipher1[rowlen*i:rowlen*(i+1)])    
                table.append([{'bit':zeroone,'serial':s},{'enc':enc1[i],'code':""},{'cipher':temp},{'aux':ZKone1[i]},{'mark':""},{'rand':""},{}])
            for i in range(elen):
                if i ==0:
                    s = entry.serial+" B"
                else:
                    s = ''
                temp = ",".join(cipher1[rowlen*i:rowlen*(i+1)])     
                table.append([{'bit':zeroone,'serial':s},{'enc':enc2[i],'code':""},{'cipher':temp},{'aux':ZKone2[i]},{'mark':""},{'rand':""},{}])
        Vtable.append(table)
    if int_tab == 2:# ver. 2
        table = []
        for entry in current.object_list:
            enc1 = entry.enc1.split(',')
            enc2 = entry.enc1.split(',')
            elen = len(enc1)
            cipher1 = entry.cipher1.split(',')
            clen = len(cipher1)
            rowlen = clen/elen
            cipher2 = entry.cipher2.split(',')
            #fake aux column
            ZKone1 = entry.ZKone1.split(',')
            ZKone2 = entry.ZKone2.split(',')
            rand1 = entry.rand1.split(',')
            rand2 = entry.rand2.split(',')
            code1 = entry.codes1.split(',')
            code2 = entry.codes2.split(',')
            if entry.mark1:
                mark1 = entry.mark1.split(',')
            else:
                mark1 = [""]*elen
            if entry.mark2:
                mark2 = entry.mark2.split(',')
            else:
                mark2 = [""]*elen
            zeroone = entry.zeroone
            for i in range(elen):
                if i ==0:
                    s = entry.serial+" A"
                else:
                    s = ''
                temp = ",".join(cipher1[rowlen*i:rowlen*(i+1)])
                table.append([{'bit':zeroone,'serial':s},{'enc':enc1[i],'code':code1[i]},{'cipher':temp},{'aux':ZKone1[i]},{'mark':mark1[i]},{'rand':rand1[i]},{'post':enc1[i][5:]}])
            for i in range(elen):
                if i ==0:
                    s = entry.serial+" B"
                else:
                    s = ''
                temp = ",".join(cipher1[rowlen*i:rowlen*(i+1)])
                table.append([{'bit':zeroone,'serial':s},{'enc':enc2[i],'code':code2[i]},{'cipher':temp},{'aux':ZKone2[i]},{'mark':mark2[i]},{'rand':rand2[i]},{'post':enc1[i][5:]}])
        Vtable.append(table)
    #end of verion 2
    BigData={'Data':Vtable} 
    return render_to_response('scroll.html', {'eid':eid,'tab':tab,'next_page':next_page, 'BigData':BigData,'col_names':col_names})         
     




def handle_uploaded_file(e, zfile,reader,sig, t):
    Aabblist = e.abbdata_set.filter(table = t)
    #check current version
    verlist = Aabblist.order_by('-version').values('version').distinct()
    v = 1
    if len(verlist)>0:
        v = verlist[0]['version']+1 #latest version+1
    #update the table
    counter = 0
    datalist = ['' for x in range(9)] #first one is useless
    bitmap = [0 for x in range(9)] #first one is useless
    for row in reader:
        if counter ==2:
            # skip the first two rows
            # mapping is not implemented    
            #key row
            entries = row.split(',')
            for i in range(1,9):
                flag = 0
                q = AbbKey(table = t, version = v,column = i, election = e)
                c = entries[3*(i-1)].strip('"')#commitment
                p = entries[3*(i-1)+1].strip('"')#plaintext
                d = entries[3*(i-1)+2].strip('"')#decommitment
                if len(c)>0:
                    q.commitment = c
                    flag+=1
                if len(p)>0:
                    q.plaintext = p
                    flag+=1
                    #decrypting all the tables
                    ver_list = Aabblist.filter(column = i).values('version').distinct()
                    if len(ver_list) !=0:
                        abb_data = Aabblist.get(column = i, version = int(ver_list[0]['version']))
                        olddata = abb_data.ciphertext.split(',')
                        buffer = ''
                        for entry in olddata:
                            #decrypt and add to database
                            chunks = entry.split()
                            key = base64.b64decode(p)
                            IV = base64.b64decode(chunks[0])
                            C = base64.b64decode(chunks[1])
                            obj = AES.new(key, AES.MODE_CBC, IV)
                            m = obj.decrypt(C).rstrip('\x00')
                            # convert 0/1 to Yes/No
                            #if i == 3 and m == '1':
                            #    m = "Yes"
                            #if i == 3 and m == '0':
                            #    m = "No"
                            #convert 0/1 to Voted/Not voted
                            #if i == 4 and m == '1':
                            #    m = "Voted"
                            #if i == 4 and m == '0':
                            #    m = "Not voted"
                            if len(buffer) > 0:
                                buffer+=','
                            buffer+=m   
                        plain = AbbData(length = abb_data.length,ciphertext = abb_data.ciphertext, plaintext = buffer, table = t, version = v,column = i, election = e)
                        plain.save()
                if len(d)>0:
                    q.decommitment = d
                    flag+=1
                if flag>0:    
                    q.save()
        if counter > 2:
            #data rows
            entries = row.split(',')
            for i in range(1,9):
                temp = entries[3*(i-1)].strip('"') #cipher
                if len(temp)>0:
                    if bitmap[i] >0:
                        datalist[i]+=','
                    bitmap[i]+=1
                    datalist[i] += temp                        
        counter += 1
    #save everything
    for i in range(1,9):
        if bitmap[i]>0:
            new = AbbData(length = counter-3,ciphertext = datalist[i], table = t, version = v,column = i, election = e)
            new.save()
    return counter-1


@csrf_exempt
def upload(request, eid = 0):
    try:
	e = Election.objects.get(EID=eid)
    except Election.DoesNotExist:
	return HttpResponse('The election ID is invalid!')
    if request.method == 'POST':
        csvfile = request.FILES['inputfile']
	reader = csvfile.read().splitlines()
	serial = ""
	enc1 = ""
	enc2 = ""
	cipher1 = ""
	cipher2 = ""
	plain1 = ""
	plain2 = ""
	decom1 = ""
	decom2 = ""
	code1 = []
	code2 = []
	n = 0
	keynum = e.keysTotal
	counter = -2 - keynum
	key = ""
	for temp in reader:
	    counter+=1
	    #first row n, k1
	    if counter ==-1-keynum:
		row = temp.split(',')
	        n = int(row[0])
		key = row[1]
	        new_r = Randomstate(election = e, notes = "k1",random = key)
	        new_r.save()
	    else: 
		if counter<0:
		    row = temp.split(',')
		    kh = Keyholder(election = e, email = row[0],hash = row[1],salt = row[2])
		    kh.save()

	    if counter >= 0 and counter%9 ==0:
		#serial key
		row = temp.split(',')
		serial = row[0]
		new_bba = Bba(election = e, serial = serial, key = row[1], n = n)
		new_bba.save()
	    if	counter >= 0 and counter%9 ==1:
		#enc1
		enc1 = temp
		row = temp.split(',')
		k = base64.b64decode(key)
		for item in row:
		    code1.append(decrypt(base64.b64decode(item),k))
            if  counter >= 0 and counter%9 ==2:
                #cipher1
                cipher1 = temp
            if  counter >= 0 and counter%9 ==3:
                #plain1
                plain1 = temp
	    if  counter >= 0 and counter%9 == 4:
		#decom1
		decom1 = temp
            if  counter >= 0 and counter%9 == 5:
                #enc2
                enc2 = temp    
                row = temp.split(',')
                k = base64.b64decode(key)
                for item in row:
                    code2.append(decrypt(base64.b64decode(item),k))
            if  counter >= 0 and counter%9 == 6:
                #cipher2
                cipher2 = temp
            if  counter >= 0 and counter%9 == 7:
                #plain2
                plain2 = temp
	    if  counter >= 0 and counter%9 == 8:
		#decom2
		decom2 = temp
		#random fake aux
		fake_aux = []
		fake_rand = []
		for i in range(n):
			fake_aux.append(base64.b64encode(os.urandom(16)))
			fake_rand.append(base64.b64encode(os.urandom(16)))
		temp1 = ",".join(fake_aux)
		temp2 = ",".join(fake_rand)
		new_abb = Abbinit(election = e, codes1 = ",".join(code1), codes2 = ",".join(code2), rand1 = temp2, rand2 = temp2 , ZKone1 = temp1, ZKone2 = temp1, zeroone = base64.b64encode(os.urandom(8)),serial = serial, enc1 = enc1, enc2 = enc2, cipher1 = cipher1, cipher2 = cipher2, plain1 = plain1, plain2 = plain2, decom1 = decom1, decom2 = decom2)
		new_abb.save()
		#clean var
		code1 = []
        	code2 = []
	e.prepared = True
	e.save()
	return HttpResponse("Success")

    else:
        return render_to_response('404.html')



@csrf_exempt
def init(request):
    if request.method == 'POST':# only accept post
        q = request.POST['question']
        start = request.POST['start']
        end = request.POST['end']
        eid = request.POST['eid']
        total = request.POST['total']
	keysTotal = request.POST['keysTotal']
        opts = []
        # maximum 100 options
        for i in range(0,100):
            temp = request.POST.get('opt'+str(i),'')
            if temp != '':
                opts.append(temp)
            else:
                break
        #create election
        start_time = time.strptime(start, "%m/%d/%Y %H:%M")
        end_time = time.strptime(end, "%m/%d/%Y %H:%M")
        new_e = Election(start = datetime.fromtimestamp(time.mktime(start_time)), end = datetime.fromtimestamp(time.mktime(end_time)), question = q, EID = eid, total = total, keysTotal = keysTotal)
        new_e.save()
        # store choices
        for x in opts:
            new_c = Choice(election = new_e, text = x)
            new_c.save()
        return HttpResponse('success')
    else:
        return render_to_response('404.html')


    
    
    


