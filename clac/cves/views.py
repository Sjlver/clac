from django.shortcuts import render

from cves.models import CveEntry

def annotate_cve(request, cve_id):
    cve_entry = CveEntry.objects.get(cve_id=cve_id)
    return render(request, 'cves/annotate_cve.html', {'cve_entry': cve_entry})
