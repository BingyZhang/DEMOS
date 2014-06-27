# -*- coding: utf-8 -*-
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render_to_response, render
from django.http import HttpResponse, HttpResponseRedirect
from crypto import commitment
import time, requests, hashlib,subprocess
from datetime import datetime
from elect_def.forms import DefForm
from elect_def.models import Election, Choice
from django.template import RequestContext
import cStringIO, zipfile, csv, copy,os, base64, random,binascii,codecs
from django.core.files import File
from django.utils import timezone
from tasks import prepare_ballot

 #support UTF-8
env = os.environ
env['PYTHONIOENCODING'] = 'utf-8'




# Create your views here.

BB_URL = "https://crypto.di.uoa.gr/demos/"

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


@csrf_exempt  # not secure, need signature or TBA
def index(request):#CAS def no captcha
    name = request.META.get('HTTP_CAS_CN_LANG_EL','')
    if name == '':# for non-greek person
        name = request.META['HTTP_CAS_CN']
    email = request.META['HTTP_CAS_MAIL']
    if request.method == 'POST':
        q = request.POST['question'].strip()
        start = request.POST['elect_start'].strip()
        end = request.POST['elect_end'].strip()
        Paffiliation = request.POST['Paffiliation'].lower().strip()
        title = request.POST['title'].lower().strip()
        Porg = request.POST['Porg'].lower().strip()
	whitelist = request.POST['Whitelist'].lower().strip()
	blacklist = request.POST['Blacklist'].lower().strip()
        total = request.POST['total'].strip()
	keyemails = request.POST['keyemails'].strip()
	pdf = request.POST.get('pdf','') 
        if pdf != '':
            intpdf = int(pdf)
        else:
            intpdf = 0
        opts = []
        # maximum 100 options
        for i in range(1,101):
            temp = request.POST.get('opt'+str(i),'')
            if temp != '':
                opts.append(temp)
            else:
                break
        if Paffiliation == '':
	    Paffiliation = '*'
	if title == '':
	    title = '*'
	if Porg == '':
	    Porg = '*'
	if total == '':
	    total = "1"
	if start =='':
	    start = timezone.now().strftime("%m/%d/%Y %H:%M")
        if end =='':
            end = timezone.now().strftime("%m/%d/%Y %H:%M")
	start_time = time.strptime(start, "%m/%d/%Y %H:%M")
	end_time = time.strptime(end, "%m/%d/%Y %H:%M")
        #EID should be hash of question start and end time  short eid
        #eid = hashlib.sha1(q + start + end).hexdigest()
	counter = Election.objects.count()
	eid = base36encode(counter+1)
        #first post to BB
        files = { 'question': q, 'start':start,'end':end, 'eid':eid,'total':total, 'keysTotal':keyemails.count(',')+1}
        for i in range(len(opts)):
            files["opt"+str(i)] = opts[i]
        r = requests.post(BB_URL+'def/',data = files, verify=False)
        #if r != "success":
        #    return HttpResponse(r)#('Error!')

        #create election
        new_e = Election(creator = name, c_email = email, Paffiliation = Paffiliation, title = title, Porg = Porg,whitelist = whitelist, blacklist = blacklist, start = datetime.fromtimestamp(time.mktime(start_time)), end = datetime.fromtimestamp(time.mktime(end_time)), question = q, EID = eid, total = total)
        new_e.save()
        # store choices
        for x in opts:
            new_c = Choice(election = new_e, text = x)
            new_c.save()
        #go through the email files
	voter_emails = []
	emailfile = request.FILES.get('emailfile','')
	if emailfile != '':
	    reader = emailfile.read().splitlines()
	    for line in reader:
		temp = line.rstrip().lower()
		if temp != '':
		    voter_emails.append(temp)
        #confirm EA
        data = []
        data.append("Question: "+q)
        for i in range(len(opts)):
            data.append("Option "+str(i+1)+": "+opts[i])
        data.append("Start time: "+start)
        data.append("End time: "+end)
	data.append("Key holders' emails: "+keyemails)
        data.append("Maximum number of voters: "+total)
        data.append("eduPersonPrimaryAffiliation: "+Paffiliation)
        data.append("Tile: "+title)
        data.append("eduPersonPrimaryOrgUnitDN: "+Porg)
	data.append("Voter whitelist: "+whitelist)
	data.append("Voter blacklist: "+blacklist)
	VBB_url = BB_URL+"vbb/"+eid+"/"
        ABB_url = BB_URL+"abb/"+eid+"/"
	#send email
	en_name = request.META['HTTP_CAS_CN']
	emailbody = "Hello "+en_name+",\n\nThe following election is created.\n"
	emailbody+= "\n".join(data)
	emailbody+= "\nVBB_url: "+VBB_url+"\n"
	emailbody+= "ABB_url: "+ABB_url+"\n"
    	emailbody+= "\nFINER  Election Authority\n"

    	#send email         
    	p = subprocess.Popen(["sudo","/var/www/finer/bingmail.sh","Election Definition No. "+eid, emailbody.encode('utf-8'),email],stdout=subprocess.PIPE,stderr=subprocess.PIPE, env=env)
    	output,err = p.communicate()
	#celery prepare ballots
	prepare_ballot.delay(new_e, int(total),len(opts), voter_emails, keyemails, intpdf)
        return render_to_response('confirm.html',{'name':name,'data':data, 'email':email,'VBB':VBB_url,'ABB':ABB_url})
    else:
        return render_to_response('def.html', {'name':name, 'form':DefForm}, context_instance=RequestContext(request))




def vote(request, eid = 0):
    try:
        e = Election.objects.get(EID=eid)
    except Election.DoesNotExist:
        return HttpResponse('The election ID is invalid!')
    return render_to_response('vote.html')






@csrf_exempt  # not secure, need signature or TBA
def pubdef(request):
    if request.method == 'POST':
        # check captcha first
        form = DefForm(request.POST)
        if not form.is_valid():
            return HttpResponse('The captcha is invalid!')
	name = request.POST['name']
	if name == "":
	    name = "Anonymous"
	email = request.POST['email']
	if email == "":
	    email = "bzhang@di.uoa.gr"
        q = request.POST['question']
        start = request.POST['elect_start']
        end = request.POST['elect_end']
        Paffiliation = request.POST['Paffiliation'].lower()
        title = request.POST['title'].lower()
        Porg = request.POST['Porg'].lower()
        total = request.POST['total']
	keyemails = request.POST['keyemails'].rstrip()	
	pdf = request.POST.get('pdf','')
	if pdf != '':
	    intpdf = int(pdf)
	else:
	    intpdf = 0
        opts = []

        # maximum 50 options cheat
        for pi in range(len(party_list)/2):
                temp = party_list[2*pi]+";"+ party_list[2*pi+1]
                opts.append(temp.decode('utf-8'))

        if Paffiliation == '':
            Paffiliation = '*'
        if title == '':
            title = '*'
        if Porg == '':
            Porg = '*'
        if total == '':
            total = "1"
        if start =='':
            start = timezone.now().strftime("%m/%d/%Y %H:%M")
        if end =='':
            end = timezone.now().strftime("%m/%d/%Y %H:%M")
        start_time = time.strptime(start, "%m/%d/%Y %H:%M")
        end_time = time.strptime(end, "%m/%d/%Y %H:%M")
        #EID should be hash of question start and end time short eid
        #eid = hashlib.sha1(q + start + end).hexdigest()
        counter = Election.objects.count()
        eid = base36encode(counter+1)
        #first post to BB
        files = { 'question': q, 'start':start,'end':end, 'eid':eid,'total':total}
        for i in range(len(opts)):
            files["opt"+str(i)] = opts[i]
        r = requests.post(BB_URL+'def/',data = files, verify=False)
        #if r != "success":
        #    return HttpResponse(r)#('Error!')
        #create election
        new_e = Election(creator = name, c_email = email, Paffiliation = Paffiliation, title = title, Porg = Porg, start = datetime.fromtimestamp(time.mktime(start_time)), end = datetime.fromtimestamp(time.mktime(end_time)), question = q, EID = eid, total = total)
        new_e.save()
        # store choices
        for x in opts:
            new_c = Choice(election = new_e, text = x)
            new_c.save()
        #go through the email files
        voter_emails = []
        emailfile = request.FILES.get('emailfile','')
        if emailfile != '':
            reader = emailfile.read().splitlines()
            for line in reader:
                temp = line.rstrip().lower()
                if temp != '':
                    voter_emails.append(temp)
        #confirm EA
        data = []
        data.append("Question: "+q)
        for i in range(len(opts)):
            data.append("Option "+str(i+1)+": "+opts[i])
        data.append("Start time: "+start)
        data.append("End time: "+end)
	#data.append("End time: "+end)
	data.append("Key holders' emails: "+keyemails)
        data.append("Maximum number of voters: "+total)
        data.append("eduPersonPrimaryAffiliation: "+Paffiliation)
        data.append("Tile: "+title)
        data.append("eduPersonPrimaryOrgUnitDN: "+Porg)
        VBB_url = BB_URL+"vbb/"+eid+"/"
        ABB_url = BB_URL+"abb/"+eid+"/"
        #send email
        emailbody = "Hello "+name+",\n\nThe following election is created.\n"
        emailbody+= "\n".join(data)
        emailbody+= "\nVBB_url: "+VBB_url+"\n"
        emailbody+= "ABB_url: "+ABB_url+"\n"
        emailbody+= "\nFINER  Election Authority\n"

        #send email         
    	p = subprocess.Popen(["sudo","/var/www/finer/bingmail.sh","Election Definition: "+q.encode('utf-8'), emailbody.encode('utf-8'),email],stdout=subprocess.PIPE,stderr=subprocess.PIPE, env=env)
    	output,err = p.communicate()
        #celery prepare ballots
        prepare_ballot.delay(new_e, int(total),len(opts), voter_emails, keyemails,intpdf)
        return render_to_response('confirm.html',{'name':name,'data':data, 'email':email,'VBB':VBB_url,'ABB':ABB_url})
    else:
        return render_to_response('pubdef.html', {'form':DefForm}, context_instance=RequestContext(request))






def TBA(request, eid = 0):
    try:
	e = Election.objects.get(EID=eid)
    except Election.DoesNotExist:
	return HttpResponse('The election ID is invalid!')
    return render_to_response('def.html')
