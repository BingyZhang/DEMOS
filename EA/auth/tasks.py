from __future__ import absolute_import

from celery import shared_task
from django.utils import timezone
from elect_def.models import Election, Choice

@shared_task
def prepare_ballot(x, y):
    print "test...creating ballot.."
    #create election
    new_e = Election(start = timezone.now(), end = timezone.now(), question = "test", EID = 1234)
    new_e.save()
    return x + y

@shared_task
def add(x, y):
    print "test...Adding.."
    return x + y


@shared_task
def mul(x, y):
    return x * y


@shared_task
def xsum(numbers):
    return sum(numbers)
