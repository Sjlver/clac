from django.core.exceptions import PermissionDenied
from django.core.urlresolvers import reverse_lazy
from django.contrib.auth import login as auth_login, logout as auth_logout, authenticate
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.db.models import Count
from django.shortcuts import render, redirect

from cves.models import CveEntry, CveAnnotation, CveAnnotationForm

@login_required(login_url=reverse_lazy('login'))
def annotate_cve(request, cve_id):
    entry = CveEntry.objects.get(cve_id=cve_id)
    try:
        annotation = CveAnnotation.objects.get(cve_entry=entry, user=request.user)
    except CveAnnotation.DoesNotExist:
        annotation = CveAnnotation(cve_entry=entry, user=request.user)

    if request.method == 'POST':
        form = CveAnnotationForm(request.POST, instance=annotation)
        if form.is_valid():
            form.save()
            return redirect('random_cve')
    else:
        form = CveAnnotationForm(instance=annotation)

    context = {
            'entry': entry,
            'annotation': annotation,
            'form': form
    }
    return render(request, 'cves/annotate_cve.html', context)

def login(request):
    if request.method == 'POST':
        # Log in the user that was specified
        username = request.POST.get('username')
        if not username:
            raise PermissionDenied

        user = authenticate(username=username, password=username)
        if user is None:
            User.objects.create_user(username, '', username)
            user = authenticate(username=username, password=username)

        if (not user.is_active) or user.is_staff or user.is_superuser:
            raise PermissionDenied

        auth_login(request, user)
        return redirect(request.POST.get('next', '/'))
    else:
        context = { 'next': request.GET.get('next', '/') }
        return render(request, 'cves/login.html', context)

def logout(request):
    auth_logout(request)
    return redirect('/')

def index(request):
    return render(request, 'cves/index.html')

def random_cve(request):
    entry = CveEntry.objects.filter(cwe_id="CWE-119").annotate(
            num_annotations=Count('cveannotation')).order_by(
            'num_annotations', '?')[0]
    return redirect('annotate_cve', cve_id=entry.cve_id)

def summary(request):
    FIELDS_OF_INTEREST = ['memory_safety_vulnerability', 'always_crash', 'memory_access',
            'control_flow_vulnerability', 'undefined_behavior_vulnerability',
            'approximate_spatial_safety', 'approximate_temporal_safety']
    
    annotations = CveAnnotation.objects.all()
    counts = {}
    for field in FIELDS_OF_INTEREST:
        counts.setdefault(field, {})
        field_choices = [c[0] for c in CveAnnotation._meta.get_field(field).choices]
        for choice in field_choices:
            field_filter = {field: choice}
            n = len(annotations.filter(**field_filter))
            counts[field][choice] = counts[field].get(choice, 0) + n
                
    return render(request, 'cves/summary.html', {
        'annotations': annotations,
        'counts': counts,
        })
