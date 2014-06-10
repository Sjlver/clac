from django.contrib.auth.models import User
from django.db import models
from django.forms import ModelForm

class CveEntry(models.Model):
    AV_CHOICES = (
            ('NETWORK', 'Network'),
            ('ADJACENT', 'Adjacent Network'),
            ('LOCAL', 'Local')
    )
    AC_CHOICES = (
            ('LOW', 'Low'),
            ('MEDIUM', 'Medium'),
            ('HIGH', 'High')
    )
    AU_CHOICES = (
            ('NONE', 'None'),
            ('SINGLE_INSTANCE', 'Single'),
            ('MULTIPLE_INSTANCES', 'Multiple')
    )
    I_CHOICES = (
            ('NONE', 'None'),
            ('PARTIAL', 'Partial'),
            ('COMPLETE', 'Complete')
    )

    cve_id = models.CharField(max_length=15, unique=True)

    access_vector = models.CharField(max_length=max([ len(c[0]) for c in AV_CHOICES]),
                                     choices=AV_CHOICES)
    access_complexity = models.CharField(max_length=max([ len(c[0]) for c in AC_CHOICES]),
                                         choices=AC_CHOICES)
    authentication = models.CharField(max_length=max([ len(c[0]) for c in AU_CHOICES]),
                                      choices=AU_CHOICES)
    confidentiality_impact = models.CharField(max_length=max([ len(c[0]) for c in I_CHOICES]),
                                              choices=I_CHOICES)
    integrity_impact = models.CharField(max_length=max([ len(c[0]) for c in I_CHOICES]),
                                        choices=I_CHOICES)
    availability_impact = models.CharField(max_length=max([ len(c[0]) for c in I_CHOICES]),
                                           choices=I_CHOICES)

    cwe_id = models.CharField(max_length=10)
    summary = models.TextField()

    def __str__(self):
        return "<Entry %s>" % self.cve_id


class CveAnnotation(models.Model):
    TRIVALUED_CHOICES = (
            ('YES',     'yes'),
            ('NO',      'no'),
            ('UNKNOWN', 'unknown')
    )
    MEMORY_ACCESS_CHOICES = (
            ('READ', 'read only'),
            ('WRITE', 'write (and read)'),
            ('UNKNOWN', 'unknown')
    )

    cve_entry = models.ForeignKey(CveEntry)
    user = models.ForeignKey(User)

    memory_safety_vulnerability = models.CharField(
            max_length=max([ len(c[0]) for c in TRIVALUED_CHOICES]),
            choices=TRIVALUED_CHOICES)
    always_crash = models.CharField(
            max_length=max([ len(c[0]) for c in TRIVALUED_CHOICES]),
            choices=TRIVALUED_CHOICES, blank=True)
    memory_access = models.CharField(max_length=max([ len(c[0]) for c in MEMORY_ACCESS_CHOICES]),
                                     choices=MEMORY_ACCESS_CHOICES,
                                     blank=True)
    control_flow_vulnerability = models.CharField(
            max_length=max([ len(c[0]) for c in TRIVALUED_CHOICES]),
            choices=TRIVALUED_CHOICES,
            blank=True)
    undefined_behavior_vulnerability = models.CharField(
            max_length=max([ len(c[0]) for c in TRIVALUED_CHOICES]),
            choices=TRIVALUED_CHOICES,
            blank=True)
    approximate_spatial_safety = models.CharField(
            max_length=max([ len(c[0]) for c in TRIVALUED_CHOICES]),
            choices=TRIVALUED_CHOICES,
            blank=True)
    approximate_temporal_safety = models.CharField(
            max_length=max([ len(c[0]) for c in TRIVALUED_CHOICES]),
            choices=TRIVALUED_CHOICES,
            blank=True)
    remarks = models.TextField(blank=True)

    def __str__(self):
        return "<Annotation for %s by %s>" % (self.cve_entry.cve_id, self.user.username)


class CveAnnotationForm(ModelForm):
    class Meta:
        model = CveAnnotation
        fields = ['memory_safety_vulnerability', 'always_crash', 'memory_access',
                  'control_flow_vulnerability', 'undefined_behavior_vulnerability',
                  'approximate_spatial_safety', 'approximate_temporal_safety',
                  'remarks']
