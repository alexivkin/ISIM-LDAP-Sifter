#!/usr/bin/python
'''
Extract ITIM configuration components from an LDIF into readable (base64 decoded) XML files

Exported are:

* Global Workflows
* Category(Operational) Workflow
* ProvisioningPolicies'
* AssemblyLines
* Forms
* Mail Templates
* ACLs

Provide the name of the ldif, exported per directions in the README

2012-2017
@author: Alex Ivkin
'''
import base64,sys,re,traceback,os,math,pprint

class LdifParser:

    def __init__(self,filename):
        self.ldif=filename
        prefix = "" # create subfolders under the same dir that the ldif is in or the current dir
        if os.path.dirname(filename) != "":
            prefix = os.path.dirname(filename)+'/' # otherwise use the folder name
        self.GlobalWorkflowExportFolder   = prefix+'Workflows'
        self.CategoryWorkflowExportFolder = prefix+'CategoryWorkflows'
        self.PPExportFolder               = prefix+'ProvisioningPolicies'
        self.ALExportFolder               = prefix+'AssemblyLines'
        self.FormsExportFolder            = prefix+'Forms'
        self.MTExportFolder               = prefix+'MailTemplates'
        self.ACLExportFolder              = prefix+'ACLs'
        self.other={}
        self.plaintext=False; # false for db2ldif, true for ldapsearch formatted files

    def parseOut(self):
        i=0
        last=-1
        try:
            print "Opening...",
            ldiffile = open(self.ldif,'r')
            num_lines = sum(1 for _ in ldiffile)
            print "%s lines." % num_lines
            ldiffile.seek(0)
            entry={}
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
                                    self.analyzeEntry(entry)
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
                                self.analyzeEntry(entry)
                            entry={}
                        elif line.startswith("#"): # skip comment
                            continue
                        elif ":" in line:
                            (key,value)=line.split(":",1)
                            key=key.lower() # ldap is case insensitive
                            value=value.strip(": ")
                            if key in entry:
                                # convert to a set
                                entry[key].append(value)
                            else:
                                entry[key]=[value]
                        elif len(entry) > 0: # tag line onto the last value
                            line=line.lstrip(' ') # remove the leading space
                            if len(entry[key]) == 1:
                                entry[key]=[entry[key][0]+line]
                            else:
                                entry[key][-1]+=line # extend the last value
                    # print progress
                    #if i>160009: break
                    percent = math.ceil(i/float(num_lines)*100*1000)/1000 # round to the tenth of a percent
                    #print "%s\r" % (math.ceil(percent*1000)/1000),
                    if percent > last :# cant simply us module because of freaky float imprecision
                        sys.stdout.write('\rParsing and saving %s: %s' % (self.ldif, "{:>5.1f}%".format(percent)))
                        last=percent
                    i+=1
            except:
                print "\nFailure parsing \"%s\" for %s\n%s, %s" % (line, entry, sys.exc_info()[0],sys.exc_info()[1])
                traceback.print_exc()
                sys.exit(2)

            if self.plaintext: # plaintext parser is backfilling, need to process the last entry
                if 'objectclass' in entry and "ou=recycleBin" not in entry['dn'][0]:
                    self.analyzeEntry(entry)
        except IOError:
            print "can't open %s!" % self.ldif
        else:
            print " done."
            print "Entries skipped:"
            pprint.pprint(self.other)
            ldiffile.close()

    def analyzeEntry(self,entry):
        #filename=name.replace(/[\\\/\[\]:;\|=,\+\*\?<>\_"]/g,"~"); // to sanitize the name
        filepattern=re.compile(r'[\\/:"*?<>|]+') # invalid filename characters on windows
        try:
            name=None
            data=None
            entryObjectclass=[o.lower() for o in entry['objectclass']]
            if 'erWorkflowDefinition'.lower() in entryObjectclass and 'erxml' in entry: # Lifecycle workflows
                # check if the guid has already been seen
                dn=entry["dn"][0]
                guid=dn[dn.find("=")+1:dn.find(",")]
#                if guid in workflowhash:
#                    name=GlobalWorkflowExportFolder+"/"+workflowhash[guid]+".xml"
#                else
                name=self.GlobalWorkflowExportFolder+"/"+(entry["erprocessname"][0] if "erprocessname" in entry else "") \
                    + "_" + (entry["erobjectprofilename"][0] if "erobjectprofilename" in entry else "") \
                    + "_" + (entry["ercategory"][0] if "ercategory" in entry else "") \
                    + "_" + guid +".xml"
                #if 'erxml' in entry:
                data=base64.b64decode(entry['erxml'][0]) if not self.plaintext else entry['erxml'][0]
                self.save(name,data)
            elif 'erALOperation'.lower() in entryObjectclass:
                filename="%s-%s-%s" % (re.search('ou=(.+),ou=assembly',entry["dn"][0]).group(1),entry['eroperationnames'][0],entry['cn'][0])
                name=self.ALExportFolder+"/"+filepattern.sub("~", filename)+".cfg"
                data=base64.b64decode(entry['eralconfig'][0]) if not self.plaintext else entry['eralconfig'][0]
                self.save(name,data)
                name=self.ALExportFolder+"/"+filepattern.sub("~", filename)+".xml"
                data=base64.b64decode(entry['erassemblyline'][0]) if not self.plaintext else entry['erassemblyline'][0]
                self.save(name,data)
            elif 'erProvisioningPolicy'.lower() in entryObjectclass: # Provisioinig Policies - ou=policies,erglobalid=00000000000000000000,ou=....
                name=self.PPExportFolder+"/"+filepattern.sub("~",entry["erpolicyitemname"][0])+"_"+entry["erglobalid"][0]+".xml";
                data=base64.b64decode(entry['erentitlements'][0]) if not self.plaintext else entry['erentitlements'][0]
                #self.ppolicies[entry["erpolicyitemname"][0]]=[entry["erpolicymembership"],entry["erreqpolicytarget"] if 'erreqpolicytarget' in entry else None,
                #                                                entry["erpolicytarget"] if 'erpolicytarget' in entry else None]
                ''' for erpolicymembership:

                    for erpolicytarget:
                    If a service instance is targeted, the value is the string representing the service instance's DN. Format: 1;<value>
                    If a service profile is targeted, the value is the name of the service profile. Format: 0;<value>
                    If all services are targeted, the value is * . Format: 2;<*>
                    If a service selection policy is targeted, the value is the name of the service profile affected by the service selection policy. Format: 3;<value>

                    erreqpolicytarget contains prerequisites in the same format
                '''
                self.save(name,data)
            elif 'erFormTemplate'.lower() in entryObjectclass: # Forms - ou=formTemplates,ou=itim,ou=....
                name=self.FormsExportFolder+"/"+filepattern.sub("~",entry["erformname"][0])+".xml"; # "_"+entry["erglobalid"][0]+
                data=base64.b64decode(entry['erxml'][0]) if not self.plaintext else entry['erxml'][0]
                self.save(name,data)
            elif 'erTemplate'.lower() in entryObjectclass: # mail templates - ou=config,ou=itim,ou=...
                if 'ertemplatename' in entry:
                    templatename=filepattern.sub("~",entry["ertemplatename"][0])
                else:
                    templatename="generic"
                name=self.MTExportFolder+"/"+templatename+"_"+entry["cn"][0]+".xml"; #
                data=""
                if 'ersubject' in entry:
                    data+="Subject: %s\n" % base64.b64decode(entry['ersubject'][0])
                if 'erenabled' in entry:
                    data+="Enabled: %s\n" % entry['erenabled'][0]
                if 'ertext' in entry:
                    data+="Text:\n"+base64.b64decode(entry['ertext'][0]) if not self.plaintext else entry['ertext'][0]
                if 'erxhtml' in entry:
                    data+="\n-------------------------------------\nXHTML:\n"+base64.b64decode(entry['erxhtml'][0]) if not self.plaintext else entry['erxhtml'][0]
                self.save(name,data)
            elif 'erObjectCategory'.lower() in entryObjectclass: # Operational and lifecycle workflows
                if 'erxml' in entry:
                    name=self.CategoryWorkflowExportFolder+"/"+filepattern.sub("~",entry["ertype"][0])+".xml"; # +"_"+entry["cn"][0]
                    data=""
                    for erxml in entry['erxml']:
                        #name = None
                        #dn = None
                        #decodederxml=base64.b64decode(entry['erxml'][0]) if not self.plaintext else entry['erxml'][0]
                        #bitsnpieces=decodederxml.split("\"")
                        #for i in range(len(bitsnpieces)):
                        #    if name is None and bitsnpieces[i].find(" name=")!=-1:
                        #        name=bitsnpieces[i+1]
                        #    if dn is None and bitsnpieces[i].find(" definitionDN=")!=-1:
                        #        dn=bitsnpieces[i+1]
                        #    if name is not None and dn is not None:
                        #        break
                        #if name is None or dn is None:
                        #    raise AssertionError("Missing name or DN")
                        #oid=dn[dn.find("=")+1:dn.find(",")]

                        # lookup op -  ou=operations,ou=itim,ou=....(objectclass=*)
                        #name=self.CategoryWorkflowExportFolder+"/"+name+"_"+entry["ertype"]+"_"+entry["ercategory"]+"_"+oid+".xml";
                        #print name
                        #save erxml'''
                        data += base64.b64decode(erxml)+"\n------------------------------------------------------------------\n"
                    self.save(name,data)
            elif 'eracl' in entry: # acls are attributes on other objects
                name=self.ACLExportFolder+"/"+filepattern.sub("~",entry["dn"][0])+".xml"; # +"_"+entry["cn"][0]
                data=""
                for acl in entry['eracl']:
                    # convert dns into  names
                    # cut the pieces off xml and stick them into a multivalued attribute
                    # var bitsnpieces=work.getString("acl").split("<systemRole>");
                    #for(var i=0; i<bitsnpieces.length;i++){
                    #cutout=bitsnpieces[i].indexOf("</systemRole");
                    #if (cutout !=-1){
                    #roledn=bitsnpieces[i].substring(0,cutout);
                    #// check with the hash first to see if we had encountered the role earlier
                    #if (hsh.get(roledn) == null){
                    #hsh.put(roledn, "known");
                    #work.getAttribute("SysRoleDNs").addValue(roledn);
                    #}
                    #}
                    #}
                    #for each SysRoleDNs
                    # lookup the name  dc=itim,dc=dom - (objectclass=erSystemRole)
                    data += base64.b64decode(acl)+"\n-----------------------------------------------------------------\n"
                    # name=contents.substring(contents.indexOf(" name=")+7,contents.indexOf(" scope=")-1);
                    # ou=work.getString("containerou");
                    # o=work.getString("containero");
                    # dn=work.getString("containerdn");
                    # depending on which one is defined
                    # filename=getExternalProperty("ACLExportFolder")+"\\"+filename+"_"+containertype+"_"+containername+".xml";
                self.save(name,data)
            else:
                key=", ".join([o for o in sorted(entryObjectclass) if o <> "top" and o <> "ermanageditem"]) # a key to count all other object classes
                if key in self.other:
                    self.other[key]+=1
                else:
                    self.other[key]=1
            # More things to process:
            #ou=category,ou=itim,ou=...
            #ou=objectProfile,ou=itim,ou=...
            #ou=serviceProfile,ou=itim,ou... - (objectclass=*)
            # lifecycle rules
            #erpolicyitemname
            #erpolicytarget
            #erjavascript
            #eridentitypolicy
            #errecertificationpolicy
            #erobjectprofile
        except:
            print "\nFailure processing %s\n%s, %s" % (entry,sys.exc_info()[0],sys.exc_info()[1])
            traceback.print_exc()
            sys.exit(2)

    def save(self,name,data):
        #if name is not None:
        #print "Saving "+ name
        d = os.path.dirname(name)
        if not os.path.exists(d):
            os.makedirs(d)
        outfile=open(name,'w')
        print >> outfile, data
        outfile.close()

if __name__ == '__main__':
    # reopen stdout file descriptor with write mode and 0 as the buffer size (unbuffered output)
    sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 0)
    if len(sys.argv) < 2:
        print __doc__
        sys.exit(1)
    parser=LdifParser(sys.argv[1])
    parser.parseOut()
