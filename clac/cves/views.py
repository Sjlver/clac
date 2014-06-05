from django.contrib.auth.decorators import login_required
from django.shortcuts import render

from cves.models import CveEntry, CveAnnotation, CveAnnotationForm

@login_required
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
    else:
        form = CveAnnotationForm(instance=annotation)

    context = {
            'entry': entry,
            'annotation': annotation,
            'form': form
    }
    return render(request, 'cves/annotate_cve.html', context)
