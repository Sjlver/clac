from django.core.exceptions import PermissionDenied
from django.core.urlresolvers import reverse_lazy
from django.contrib.auth import login as auth_login, logout as auth_logout, authenticate
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
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

        try:
            user = authenticate(username=username, password=username)
        except User.DoesNotExist:
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
    entry = CveEntry.objects.order_by('?')[0]
    return redirect('annotate_cve', cve_id=entry.cve_id)
