#!/usr/bin/env python3

import sys

from lxml import etree
from cves.models import CveEntry

class CveParseError(Exception):
    pass

def load_cves(filename):
    """Reads CVE data from an XML file. Returns a list of hashes."""
    doc = etree.parse(filename)
    cves = []
    for entry in doc.iter('{*}entry'):
        try:
            cve = {}
            for property in ['cve-id', 'access-vector', 'access-complexity',
                    'authentication', 'confidentiality-impact', 'integrity-impact',
                    'availability-impact', 'summary']:
                try:
                    django_name = property.replace('-', '_')
                    cve[django_name] = entry.find('.//{*}' + property).text
                except AttributeError as e:
                    cve_id = cve.get('cve_id', 'unknown cve')
                    raise CveParseError("error reading %s: cannot read property %s" % (cve_id, property))

            try:
                cve['cwe_id'] = entry.find('{*}cwe').get('id')
            except AttributeError:
                cve_id = cve.get('cve_id', 'unknown cve')
                raise CveParseError("error reading %s: cannot read cwe_id" % cve_id)

            cves.append(cve)
        except CveParseError as e:
            print("Skipping CVE:", e)

    return cves


def save_cve(cve):
    cve_object = CveEntry.objects.create(**cve)
    cve_object.save()

if __name__ == '__main__':
    cve_file = sys.argv[1]
    cves = load_cves(cve_file)
    print("loaded %d cves" % len(cves))

    for cve in cves:
        save_cve(cve)
