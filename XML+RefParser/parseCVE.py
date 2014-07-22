import xml.sax
import urllib2
from thread import start_new_thread,allocate_lock
import time

#lock to protect num_threads var
lock = allocate_lock()

#number of threads currently active
num_threads = 0

#maximum number of threads to spawn
max_threads = 50

#Function to handle an CVE; it receives as params the title of the CVE, the text #description, as well as a list of
#references.
#The function is called in a new thread, as it can be slow to retrieve URLs
def handleContent(title, description, urls):
  global num_threads, lock
  content = description

  #concatenate info from URLs in a single large string
  for url in urls:
    try:
      page = urllib2.urlopen(url)
      content = content + "\n" + url + "-----------------------"
      content = content + "\n" + page.read()
      content = content + "\n" + "-----------------------------------------\n"
    except Exception, e:
      pass

  #append a space and ( to the system call, e.g. "open" becomes " open("
  if any( (" " + call + "(") in content for call in syscalls):        

    #write description + reference contents for CVEs that match the query
    with open("CVEs/" + title + ".txt", 'w') as f:
      #print matching syscalls in the file
      for call in syscalls:
        if (" " + call + "(") in content:
          f.write(call + "\n")
      f.write("\n\n")
      f.write(content)
  lock.acquire()
  num_threads -= 1
  lock.release()

class CVEContentHandler(xml.sax.ContentHandler):

  def __init__(self):
    xml.sax.ContentHandler.__init__(self)
    self.currentVulnerability = None
    self.content = ""
    self.inVulnerability = False
    self.inTitle = False
    self.inCVE = False
    self.inURL = False
    self.inDescription = False
    self.inReference = False
    self.count = 1
    self.URLs = []
 
  def startElement(self, name, attrs):
    if name == "Vulnerability":
      self.inVulnerability = True
    if name == "Title":
      self.inTitle = True
    if name == "CVE":
      self.inCVE = True
    if name == "Reference":
      self.inReference = True
    if name == "URL" and self.inReference == True:
      self.inURL = True
    if name == "Note" and attrs.getValue("Type") == "Description":
      self.inDescription = True
 
  def endElement(self, name):
    global num_threads, lock, max_threads
    
    if name == "Vulnerability":

      #limit number of worker threads
      while num_threads > max_threads:
        time.sleep(0.5)

      lock.acquire()
      num_threads += 1
      lock.release()
      
      start_new_thread(handleContent, (self.currentVulnerability, self.content, self.URLs))
      
      self.inVulnerability = False
      self.currentVulnerability = None
      self.content = ""
      self.URLs = []

    if name == "Title":
      self.inTitle = False
    if name == "CVE":
      self.inCVE = False
    if name == "Reference":
      self.inReference = False
    if name == "URL":
      self.inURL = False
    if name == "Note":
      self.inDescription = False
 
  def characters(self, content):
    if self.inDescription and len(content.strip()) > 0:
      self.content = self.content + content.strip() + " "
    if self.inURL:
      self.URLs.append(content.strip())
    if self.inTitle:
      self.currentVulnerability = content
      print(`self.count` + ": " + content.strip())
      self.count += 1
 
def main(sourceFileName):
  global num_threads

  source = open(sourceFileName)
  xml.sax.parse(source, CVEContentHandler())

  #wait for all worker threads to finish
  while num_threads > 0:
    time.sleep(1)
 
if __name__ == "__main__":

  #list of syscalls to search for, one per line
  with open('syscalls.txt') as f:
    syscalls = f.readlines()
  syscalls = [x.strip('\n') for x in syscalls]
  main("allitems-cvrf.xml")
