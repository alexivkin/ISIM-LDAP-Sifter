#!/usr/bin/python
'''
Extracts data from LDIF into subfiles. Skips over people and accounts, disables services unless -a is given. Picks random 10 people to create an import

Useful for converting Prod data to a subset that is safe and confidential for importing into Dev and QA

dataextractor.py [-a][-d] <name of the ldif>
 -a to extract all data. If no -a is supplied the data is truncated and modified for non-Prod environments. E.g only 10 random people are exported, services are disabled by modifying erurl, service supporting data (groups etc) is skipped.
 -d to create removal ldifs, so data can be replaced. It uses DNs from the input LDIF. The side effect is that any DNs that are in the LDAP, but not in input LDIF will not be removed.
   To clean all of the existing entries run dataextractor on the ldapdump from the current LDAP or just use the build-cleaner-from-ldif.sh script

This code assumes the base DN is dn=com. Recycle bin is always skipped.

* extract-acletc.ldif, extract-acletc-del.ldif - ou=[name],DC=COM and eracl attributes of erglobalid=00000000000000000000,ou=[name],DC=COM
* extract-system.ldif, extract-system-del.ldif - ou=systemUser,ou=itim,ou=[name],DC=COM
* extract-config.ldif, extract-config-del.ldif - ou=itim,ou=[name],DC=COM
	* ou=policies
	* ou=config
	* ou=accesstype
	* ou=assemblyline
	* ou=privilegerules
	* cn=challenges
	* ou=operations
	* ou=objectprofile
	* ou=serviceprofile
	* ou=lifecycleprofile
	* ou=formtemplates
	* ou=category
	* ou=joindirectives
* extract-custom.ldif, extract-custom-del.ldif - ou=data,ou=[name],dc=com
* extract-people.ldif - ou=people,erglobalid=00000000000000000000,ou=[name],DC=COM
	* ou=people
	* ou=accounts
* extract-srvics.ldif, extract-srvics-del.ldif - ou=services,erglobalid=00000000000000000000,ou=[name],DC=COM
* extract-tenant.ldif, extract-tenant-del.ldif - erglobalid=00000000000000000000,ou=[name],dc=com:
	* ou=policies
	* ou=sysroles
	* ou=roles
	* ou=orgchart
	* ou=workflow
* extract-other.ldif - everything else that did not fit into the above categories


2012-2017
@author: Alex Ivkin
'''
import base64, sys, re, traceback, os, pprint, operator, csv, math, subprocess, random, textwrap
from collections import defaultdict # dicts that need no pre-init, for simpler code

def Tree(): # recursive dict storage representing an [ldap] tree
    return defaultdict(Tree)

class LdifParser:

    def __init__(self,filename,allpeople,deldata):
        self.ldif=filename
        self.allpeople=allpeople
        self.deldata=deldata
        self.testcount=10 # how many random test people to export/generate
        #self.accountsf=os.path.splitext(filename)[0]+".accounts"+ext
        # hash-o-hashes
        self.accounts={}
        self.services={}
        self.people={}
        self.neededpeople={}
        self.roles={}
        self.ppolicies={}
        self.ous={}
        self.other={}
        self.objects=defaultdict(int) # a dict that auto inits to 0 for new keys
        self.peoplebyclass=defaultdict(list)
        self.ldaptree=Tree()
        self.serviceprofiles={'eritimservice':'Built-in'} # init in with a default entry
        self.serviceprofileskeys={}
        self.plaintext=False; # false for db2ldif, true for ldapsearch formatted files
        self.tenant_dns=["ou=policies","ou=sysroles","ou=roles","ou=orgchart","ou=workflow"]
        self.people_dns=["ou=people","ou=accounts"]
        self.system_dns=["ou=systemuser"]
        self.srvics_dns=["ou=services"]
        self.custom_dns=["ou=data","*"] # star means all non-parent (i.e. leaf) entries
        self.config_dns=["ou=constraints","erdictionaryname=password","ou=policies","ou=config","ou=accesstype","ou=assemblyline","ou=privilegerules","cn=challenges","ou=operations","ou=objectprofile","ou=serviceprofile","ou=lifecycleprofile","ou=formtemplates","ou=category","ou=joindirectives"]
        # the following is in enrole.properties password.attributes. Lowercase it
        self.encrypted_attributes=['ersynchpassword','erservicepassword','erservicepwd1','erservicepwd2','erservicepwd3','erservicepwd4','eraddomainpassword','erpersonpassword','ernotespasswdaddcert','eritamcred','erep6umds','erposixpassphrase']
        self.extradc=False # true if there is a one more [useless] dc below dc=com

    def parseOut(self):
        i=0
        last=-1

        with open("extract-tenant.ldif","w") as self.tenantfh, open("extract-srvics.ldif","w") as self.srvicsfh, open("extract-custom.ldif","w") as self.customfh,open("extract-system.ldif","w") as self.systemfh,\
             open("extract-people.ldif","w") as self.peoplefh, open("extract-config.ldif","w") as self.configfh, open("extract-acletc.ldif","w") as self.aclsfh,  open("extract-others.ldif","w") as self.othersfh, open(self.ldif,'r') as ldiffile:
            print "Opening...",
            # fastest line count using wc
            p = subprocess.Popen(['wc', '-l', self.ldif], stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            result, err = p.communicate()
            if p.returncode != 0:
                raise IOError(err)
            num_lines=int(result.strip().split()[0]) # 118593960
            print "%s lines." % num_lines
            if self.deldata:
                self.tenantdfh = open("extract-tenant-del.ldif","w")
                self.srvicsdfh = open("extract-srvics-del.ldif","w")
                self.customdfh = open("extract-custom-del.ldif","w")
                self.configdfh = open("extract-config-del.ldif","w")
                self.aclsdfh   = open("extract-acletc-del.ldif","w")
                self.systemdfh = open("extract-system-del.ldif","w")
            # ldiffile.seek(0)
            entry=defaultdict(list)
            key=''
            try:
                for fullline in ldiffile:
                    line=fullline.rstrip('\n\r') # keep spaces but remove EOLs
                    if not self.plaintext and not entry and line.startswith("erglobalid="):
                        self.plaintext=True;
                        print "plaintext format ",
                    if self.plaintext: # ldapsearch plaintext format
                        if re.match("erglobalid=.*DC=COM$",line,re.I): # analyze old and start a new entry
                            if entry:
                                if 'objectclass' in entry and "ou=recycleBin" not in entry['dn'][0] : # if it is a valid entry and not in the trash
                                    self.dumpEntry(entry)
                                entry={}
                            entry['dn']=[line]
                        elif re.match(r"[a-zA-Z]+=.*[^;]$",line): # it's so specific to make sure we ignore any javascript - the side effect is skipping the ldap attributes that have values ending in ;
                            (key,value)=line.split("=",1)
                            key=key.lower() # ldap is case insensitive
                            value=value.strip("=")
                            if value <> "NOT ASCII": # this means this value is lost in ldapsearch export
                                if key in entry:
                                    entry[key].append(value)
                                else:
                                    entry[key]=[value]
                        elif len(line)>0 and len(entry) > 0: # tag line onto the last value. Skipping empty lines to make sure we dont duplicate \n, but the sideeffect is removal of blank lines from the multiline attribute values
                            #line=line.lstrip(' ') # remove the leading space
                            if len(entry[key]) == 1:
                                entry[key]=[entry[key][0]+line+"\n"] #  add \n for readability (it's plaintext not base64)
                            else:
                                entry[key][-1]+=line+"\n" # extend the last value
                        #else:
                        #    print "Error: ", line
                    else: # classical format (softerra, db2ldif)
                        if line=='': # end of an entry
                            if 'objectclass' in entry and "ou=recycleBin" not in entry['dn'][0] : # if it is a valid entry and not in the trash
                                self.dumpEntry(entry)
                            entry=defaultdict(list)
                            entry['raw']=""
                        elif line.startswith("#"): # skip comment
                            continue
                        elif ":" in line:
                            (key,value)=line.split(":",1)
                            key=key.lower() # ldap is case insensitive
                            value=value.strip(": ")
                            entry[key].append(value)
                        elif len(entry) > 0: # tag line onto the last value
                            line=line.lstrip(' ') # remove the leading space
                            if len(entry[key]) == 1:
                                entry[key]=[entry[key][0]+line]
                            else:
                                entry[key][-1]+=line # extend the last value
                        entry['raw']+=fullline
                    #if i>16000090: break
                    # print progress
                    percent = math.ceil(i/float(num_lines)*100*1000)/1000 # round to the tenth of a percent
                    if percent > last :# cant simply us module because of freaky float imprecision
                        sys.stdout.write('\rParsing %s: %s' % (self.ldif, "{:>5.1f}%".format(percent)))
                        last=percent
                    i+=1
            except:
                print "\nFailure pasing \"%s\" for %s\n%s, %s" % (line, entry, sys.exc_info()[0],sys.exc_info()[1])
                traceback.print_exc()
                sys.exit(2)

            if self.plaintext: # plaintext parser is backfilling, need to process the last entry
                if 'objectclass' in entry and "ou=recycleBin" not in entry['dn'][0]:
                    self.dumpEntry(entry)
            # second pass to dump required people records
            if not allpeople:
                if len(self.people.keys()) == 0:
                    print "Could not find any person records to export"
                else:
                    print "\nExporting people...%s from roles, %s from workflows, %s test." % (len([k for k,v in self.neededpeople.items() if v==1]),len([k for k,v in self.neededpeople.items() if v==2]),self.testcount)
                    # extract required entries
                    for k in self.neededpeople.keys():
                        #print "%s=%s" % (k,self.neededpeople[k])
                        if k in self.people:
                            print >> self.peoplefh, self.people[k]['raw'],
                        else:
                            print "Missing %s" % k
                    print >> self.peoplefh, ""
                    # now extract random ppl, and mix in their attributes from other random people
                    for i in range(self.testcount):
                        print >> self.peoplefh, self.people[random.choice(self.people.keys())]['raw']

                        # mix their attributes with random people of the same set of object classes
                        '''
                        person=self.people[random.choice(self.people.keys())]
                        personClasses=tuple(sorted([o.lower() for o in person['objectclass']]))
                        print >> self.peoplefh, "dn:", person['dn'][0]
                        cndonor=self.people[random.choice(self.peoplebyclass[personClasses])]
                        for k in person.keys():
                            if k=='raw' or k=='dn':
                                continue
                            if k=='cn' or k=='sn' or k.lower()=='givenname' or k.lower()=='displayname':
                                similarperson=cndonor
                            else:
                                similarperson=self.people[random.choice(self.peoplebyclass[personClasses])]
                            if k in similarperson:
                                person[k]=similarperson[k]
                            #else:
                            #    print "Person %s: Similar person %s is missing %s" % (person['cn'],similarperson['cn'],k)
                            for j in person[k]:
                                print >> self.peoplefh, "%s: %s" % (k,"\n ".join(textwrap.wrap(text, 100))
                        '''

            print "done"
        #except IOError:
        #    print "can't open %s!" % self.ldif
        #else:
        #    ldiffile.close()

    def dumpEntry(self,entry):
        entryObjectclass=[o.lower() for o in entry['objectclass']]
        dn=entry['dn'][0] if ',' in entry['dn'][0] or ('=' in entry['dn'][0] and '=' <> entry['dn'][0][-1]) else base64.b64decode(entry['dn'][0]) # guessing if it's base64
        dnlist=re.split(r'(?<!\\),',dn.lower()) # split by , but not \,
        dnlist.reverse() # LDAP tree style addressing (root at the beginning)
        if "domain" in entryObjectclass and len(entry["dc"])>1:
            self.extradc=True
        if self.extradc:
            dnlist.pop(1) # remove extra dc if present
        # todo refactor for a more elegant way is to tie dn lists to filehandles and do the output it in a generic way
        if len(dnlist) == 2 and dnlist[0] == "dc=com":
            if "ertenant" in entryObjectclass:
                # grab the tenant props
                print >> self.aclsfh, "dn: "+dn
                print >> self.aclsfh, "changetype: modify"
                for (attr,val) in entry.items():
                    if attr not in ["dn","control","ou","objectclass","ibm-entryuuid","raw"]: # raw is the one we create
                        print >> self.aclsfh, "replace: "+attr
                        print >> self.aclsfh, attr+": "+val[0]
                        print >> self.aclsfh, "-"
                print >> self.aclsfh, ""
            elif "*" in self.custom_dns and "ibm-replicaGroup" not in entryObjectclass:
                print >> self.configfh, entry['raw'],
        elif len(dnlist) == 3 and dnlist[2] == "erglobalid=00000000000000000000" and "eracl" in entry and len(entry["eracl"]) > 0:
            # special format - start with the ldapmodify header
            print >> self.aclsfh, "dn: "+dn
            print >> self.aclsfh, "changetype: modify"
            for acl in entry["eracl"]:
                print >> self.aclsfh, "add: eracl"
                print >> self.aclsfh, "eracl:: "+acl # double colon to indicate base64 encoded data
                print >> self.aclsfh, "-"
            if self.deldata:
                # nukem all
                print >> self.aclsdfh, "dn: "+dn
                print >> self.aclsdfh, "changetype: modify"
                print >> self.aclsdfh, "delete: eracl"
        elif len(dnlist) > 3:
            if dnlist[2] == "erglobalid=00000000000000000000":
                if dnlist[3] in self.tenant_dns:
                    print >> self.tenantfh, entry['raw'],
                    if self.deldata:
                        print >> self.tenantdfh, "dn: "+dn
                        print >> self.tenantdfh, "changetype: delete\n"
                if allpeople:
                    if dnlist[3] in self.people_dns:
                        if not (len(dnlist)==4 or (len(dnlist)==5 and dnlist[4]=="ou=0")): # or dnlist[5]=="erglobalid=00000000000000000007"): # skip already existing base entries and System Administrator
                            print >> self.peoplefh, entry['raw'],
                else:
                    if dnlist[3] == "ou=people":
                        self.people[dn.lower()]=entry       # hash ppl for later
                        self.peoplebyclass[tuple(sorted(entryObjectclass))].append(dn.lower())
                    if dnlist[3] == "ou=roles" and "owner" in entry: # for maintaining referential integrity
                        self.neededpeople[entry["owner"][0].lower()]=1
                if dnlist[3] in self.srvics_dns:
                    if allpeople:
                        print >> self.srvicsfh, entry['raw'],
                    else:
                        if len(dnlist) > 4 and 'erITIMService' not in entry['objectclass']:  # skip over the basic itim service and the main OU container
                            # add len(dnlist) == 5 to skip over subentries (service groups)
                            disabledservice=re.sub(r'er(itdi|)*url: (.*)',r'er\1url: disabled|\2',entry['raw'],flags=re.IGNORECASE)
                            #print disabledservice
                            print >> self.srvicsfh, disabledservice,
                    if self.deldata:
                        print >> self.srvicsdfh, "dn: "+dn
                        print >> self.srvicsdfh, "changetype: delete\n"
            elif dnlist[2] == "ou=itim":
                if dnlist[3] in self.config_dns:
                    print >> self.configfh, entry['raw'],
                    if self.deldata:
                        print >> self.configdfh, "dn: "+dn
                        print >> self.configdfh, "changetype: delete\n"
                if allpeople and dnlist[3] in self.system_dns:
                    print >> self.systemfh, entry['raw'],
                    if self.deldata:
                        print >> self.systemdfh, "dn: "+dn
                        print >> self.systemdfh, "changetype: delete\n"
                if 'erWorkflowDefinition'.lower() in entryObjectclass and 'erxml' in entry: # Lifecycle workflows, grep them for people references
                    data=base64.b64decode(entry['erxml'][0]) if not self.plaintext else entry['erxml'][0]
                    #print "Unwrapping ", entry["erprocessname"][0]
                    persondn=re.search("erglobalid=[^,]*,ou=0,ou=people,erglobalid=00000000000000000000,ou=[^,]*,dc=com",data,flags=re.MULTILINE|re.IGNORECASE)
                    if persondn is not None:
                        self.neededpeople[persondn.group()]=2
            elif dnlist[2] in self.config_dns: # for entries under the ou=itim,dc=com
                print >> self.configfh, entry['raw'],
                if self.deldata:
                    print >> self.configdfh, "dn: "+dn
                    print >> self.configdfh, "changetype: delete\n"
            elif dnlist[2] in self.custom_dns: # dumpall
                print >> self.customfh, entry['raw'],
                if self.deldata:
                    print >> self.customdfh, "dn: "+dn
                    print >> self.customdfh, "changetype: delete\n"
            else:
                print >> self.othersfh, entry['raw'],
        else:
            print >> self.othersfh, entry['raw'],
            # remove encrypted attributes
            #enc_att=[x in entry for x in self.encrypted_attributes]
            #if any(enc_att):
            #    print "%s matches %s" % (dn,[x for x,e in zip(self.encrypted_attributes,enc_att) if e])

if __name__ == '__main__':
    # reopen stdout file descriptor with write mode and 0 as the buffer size (unbuffered output)
    sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 0)
    if len(sys.argv) < 2:
        print __doc__
        sys.exit(1)
    filename=sys.argv[len(sys.argv)-1] # last argument
    allpeople=True if sys.argv[1] == "-a" or (len(sys.argv)>=3 and sys.argv[2] == "-a") else False
    deldata=True if sys.argv[1] == "-d" or (len(sys.argv)>=3 and sys.argv[2] == "-d") else False
    parser=LdifParser(filename,allpeople,deldata)
    parser.parseOut()
