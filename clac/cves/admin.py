from django.contrib import admin
from cves.models import CveEntry, CveAnnotation

# Register your models here.
admin.site.register(CveEntry)
admin.site.register(CveAnnotation)
