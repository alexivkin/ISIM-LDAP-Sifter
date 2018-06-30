#!/usr/bin/python
'''
Analyzes LDIF and produces many stats and an LDAP tree overview
Uses a bunch of memory - close to the size of the original ldif

inspector.py [-c] <name of the ldif>

 -c to output stats as csv files

Needs PrettyTable
sudo apt-get install python-prettytable

2012-2017
@author: Alex Ivkin
'''
import base64, sys, re, traceback, os, pprint, operator, csv, math, prettytable, subprocess
from collections import defaultdict # dicts that need no pre-init, for simpler code

def Tree(): # recursive dict storage representing an [ldap] tree
    return defaultdict(Tree)

class LdifParser:

    def __init__(self,filename,csvformat):
        self.ldif=filename
        self.csvformat=csvformat
        #self.accountsf=os.path.splitext(filename)[0]+".accounts"+ext
        # hash-o-hashes
        self.accounts={}
        self.services={}
        self.people={}
        self.roles={}
        self.ppolicies={}
        self.ous={}
        self.other={}
        self.objects=defaultdict(int) # a dict that auto inits to 0 for new keys
        self.ldaptree=Tree()
        self.serviceprofiles={'eritimservice':'Built-in'} # init in with a default entry
        self.serviceprofileskeys={}
        self.plaintext=False; # false for db2ldif, true for ldapsearch formatted files

    def parseOut(self):
        i=0
        last=-1
        try:
            print "Opening...",
            # fastest line count using wc
            p = subprocess.Popen(['wc', '-l', self.ldif], stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            result, err = p.communicate()
            if p.returncode != 0:
                raise IOError(err)
            num_lines=int(result.strip().split()[0])
            #for num_lines,l in enumerate(ldiffile):
            #   pass
            #num_lines+=1
            #num_lines = sum(1 for _ in ldiffile)
            #print llen/float(num_lines)
            print "%s lines." % num_lines
            ldiffile = open(self.ldif,'r')
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
                                if 'objectclass' in entry:
                                    if "ou=recycleBin" not in entry['dn'][0] : # if it is a valid entry and not in the trash
                                        self.analyzeEntry(entry)
                                    else:
                                        self.countEntry(entry) # just add it to the tree, dont analyze
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
                            if 'objectclass' in entry:
                                if "ou=recycleBin" not in entry['dn'][0] : # if it is a valid entry and not in the trash
                                    self.analyzeEntry(entry)
                                else:
                                    self.countEntry(entry) # just add it to the tree, dont analyze
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
                    #if i>1600009: break
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
                    self.analyzeEntry(entry)
            # second pass to fill in the values the first pass missed
            print "\nRemapping ...",
            # servicetypes do not backreference well, so we do a second pass and readability conversion right here
            #print self.serviceprofiles
            #print self.services
            for (k,v) in self.services.items():
                if v['type'] in self.serviceprofiles:
                    serviceclass=self.serviceprofiles[v['type']]
                    if serviceclass == 'com.ibm.itim.remoteservices.provider.itdiprovider.ItdiServiceProviderFactory':
                        serviceclass='TDI'
                    elif serviceclass == 'com.ibm.itim.remoteservices.provider.dsml2.DSML2ServiceProviderFactory':
                        serviceclass='DSML'
                    elif serviceclass == 'com.ibm.itim.remoteservices.provider.feedx.InetOrgPersonToTIMxPersonFactory':
                        serviceclass='LDAPPersonFeed'
                    elif serviceclass == 'com.ibm.itim.remoteservices.provider.manualservice.ManualServiceConnectorFactory':
                        serviceclass='Manual'
                    elif serviceclass == 'com.ibm.itim.remoteservices.provider.feedx.ADToTIMxPersonFactory':
                        serviceclass='ADPersonFeed'
                    elif serviceclass == 'com.ibm.itim.remoteservices.provider.feedx.CSVFileProviderFactory':
                        serviceclass='CSV'
                    self.services[k]['class']=serviceclass
            # process provisioning policies
            for (k,v) in self.ppolicies.items():
                if v['members'] is not None: # convert role dns to names
                    rolelist=[]
                    for role in v['members']: # loop over req targets
                        if role[2:].lower() in self.roles:
                            rolelist.append(self.roles[role[2:].lower()]['name']) # convert dn to name
                        else:
                            rolelist.append(role[2:])
                    self.ppolicies[k]['members']=rolelist
                if v['required'] is not None: # convert service dns to service names
                    svclist=[]
                    for service in v['required']: # loop over req targets
                        if service[2:].lower() in self.services:
                            svclist.append(self.services[service[2:].lower()]['name']) # convert dn to name
                        else:
                            svclist.append(service[2:])
                    self.ppolicies[k]['required']=svclist
                if v['target'] is not None: # convert services in target types to service names
                    svclist=[]
                    for service in v['target']: # loop over req targets
                        if service[2:].lower() in self.services:
                            svclist.append(self.services[service[2:].lower()]['name']) # convert dn to name
                        else:
                            svclist.append(service[2:])
                    self.ppolicies[k]['target']=svclist
            # OUs
            for (k,v) in self.ous.items():
                #if 'parent' in v
                allparents=self.ouLineage(v['parent'])
                self.ous[k]['name']=((allparents+" > ") if allparents is not None else '')+v['name']
            for (k,v) in self.ous.items(): # after we're done parsing...
                self.ous[k].pop('parent') # Fratricide. we have them remembered thou

            # common classes and attributes for ppl
            pplcount={"Total":0,"Active":0,"Suspended":0}
            classonly=defaultdict(int)
            attronly=defaultdict(int)
            for (k,v) in self.people.items():
                for c in v['class']:
                    classonly[c]+=1
                for c in v['attributes']:
                    attronly[c]+=1
                pplcount["Total"]+=1
                pplcount["Active" if v['status']=='0' else "Suspended"]+=1

            commonclasses=set()
            for (k,v) in classonly.items():
                if v == pplcount['Total']:
                    commonclasses.add(k)
            commonattributes=set()
            for (k,v) in attronly.items():
                if v == pplcount['Total']:
                    commonattributes.add(k)
            # process statistics
            pplbyroles=defaultdict(int) # 0 for any new key
            pplbyclass=defaultdict(int)
            pplbyou=defaultdict(int)
            pplbyattributes=defaultdict(int)
            for (k,v) in self.people.items():
                # add people counts to roles
                newroles=[]
                for r in v['roles']:
                    if r in self.roles:
                        self.roles[r]['members']+=1
                        newroles.append(self.roles[r]['name'])
                    else:
                        newroles.append(r)
                #self.people[k]['roles']=newroles
                self.people[k]['roles']=len(newroles)
                fr=tuple(sorted(newroles)) # tuple instead of the frozenset, since sets are unordered and show up randomly even when created from a sorted list
                #pplpyroles.setdefault(fr,[]).append(p)
                pplbyroles[fr]+=1
                pplbyclass[tuple(sorted(set(v['class'])-commonclasses))]+=1
                pplbyattributes[tuple(sorted(set(v['attributes'])-commonattributes))]+=1

                if v['ou'] in self.ous:
                    self.ous[v['ou']]['people']+=1
                    self.people[k]['ou']=self.ous[v['ou']]['name']

                pplbyou[self.people[k]['ou']]+=1
            # print collected stats
            print "done\nSaving :",
            self.saveDict(self.services,"services")
            self.saveDict(self.roles,"roles")
            self.saveDict(self.ppolicies,"ppolicies")
            self.saveDict(self.ous,"ous")
            #self.saveDict(self.people,"people",issorted=False) # sorting takes too long
            self.saveMultiDict(self.other,"other")
            with open(os.path.splitext(filename)[0]+".stats",'w') as o:
                self.ptTree("LDAP Tree",self.ldaptree,o)
                self.ptDict("People",pplcount,o)
                self.ptDict("Objects",self.objects,o)
                self.ptDict("Object class used by people",classonly,o)
                self.ptDict("Person Object classes",pplbyclass,o)
                self.ptDict("Person OUs",pplbyou,o)
                self.ptDict("Person Roles",pplbyroles,o)
                self.ptDict("Attribute used by people",attronly,o)
                self.ptDict("Person Attributes",pplbyattributes,o)
            print "done"
        except IOError:
            print "can't open %s!" % self.ldif
        else:
            ldiffile.close()

    def ptDict(self,name, dicttosave,filehandle):
        print "%s %s..." % (len(dicttosave),name),
        print >> filehandle, "%s : %s types\n" % (name,len(dicttosave))
        x = prettytable.PrettyTable()
        x.add_column("Value",dicttosave.values()) # since it's a hash-o-hashes.v.values()
        x.add_column("Key",dicttosave.keys()) # since it's a hash-o-hashes.v.values()
        x.sortby="Value"
        x.align="l"
        print >> filehandle, x
        print >> filehandle, "\n"

    def saveDict(self,dicttosave,filename,issorted=True):
        print "%s %s..." % (len(dicttosave),filename),
        # save/print a dict values (not keys)
        fields=dicttosave.itervalues().next().keys()
        #if issorted:
        #    dicttosave=sorted(indict.items(),key=operator.itemgetter(1)) # sort by key - alternatively could sort in prettytable using x.sortby = "name"
        #else:
        #    dicttosave=indict.values()
        if "name" in fields:    # put name to the first column
            fields.remove('name')
            fields.insert(0,'name')

        with open(os.path.splitext(self.ldif)[0]+"."+filename+(".csv" if self.csvformat else ""),'w') as o:
            if self.csvformat:
                #print >> self.drf, "".join(["Service Name".ljust(50),"Service type (class)".ljust(40),"URL".ljust(50),"Active".ljust(10),"Suspended".ljust(10),"Orphans".ljust(10)])
                c=csv.DictWriter(o,fields) # get keys of a hash of a random element
                c.writeheader()
                for (k,v) in dicttosave.items():
                    c.writerow(v)#v[0],v[1]+' ('+str(v[6])+')'),v[2],v[3],v[4],v[5])
                #csv.writer(o).writerows(sorted_services)
            else:
                x = prettytable.PrettyTable()
                #x.set_style(prettytable.PLAIN_COLUMN)# prettytable.MSWORD_FRIENDLY)
                x.field_names=fields
                if issorted and "name" in fields:    # put name to the first column
                    x.sortby = "name"
                x.align="l"
                for (k,v) in dicttosave.items():
                    x.add_row([v[f] for f in fields]) # since it's a hash-o-hashes.v.values()
                print >> o, x

    def saveMultiDict(self,dicttosave,filename):
        print "%s %s..." % (len(dicttosave),filename),
        with open(os.path.splitext(self.ldif)[0]+"."+filename,'w') as o:
            for (k,v) in dicttosave.items():
                print >> o, "%s (%s items):" % (k,len(v))
                for i in v:
                    print >> o, "    ", i

    def ouLineage(self,oudn):
        # recursive resolver for the OU tree structure - walk up the inheritance and resolve DNs into names
        if oudn in self.ous:
            line=self.ouLineage(self.ous[oudn]['parent'])
            return ((line+" > ") if line is not None else '')+self.ous[oudn]['name'] # decode name

    def ptTree(self,name, treetosave,filehandle):
        # print an LDAP tree
        print "%s..." % name,
        print >> filehandle, "%s : \n" % name #%s leafs\n" % (name,len(dicttosave))
        #pprint.pprint(treetosave, stream=filehandle)
        print >> filehandle, self.treePrinter(treetosave)
        print >> filehandle, "\n"

    def treePrinter(self,tree,level=0,full=False): # full to print leaves
        # recursive tree printer
        strtree=""
        for (k,v) in tree.items():
            strtree+="%s%s: %s items\n" % ('   '*level,k,len(v) if type(v) is dict else 0)
            if type(v) is dict:
                if full or self.maxheight(v)>1:
                    strtree+=self.treePrinter(v,level+1)
            else:
                if full:
                    strtree+="%s%s\n" % ('   '*(level+1),v)
        return strtree

    def maxheight(self,tree,h=0):
        # find max tree height
        #print "%s:%s" % (tree,h)
        if type(tree) is not dict:
            return h
        return max(self.maxheight(v,h+1) for k,v in tree.iteritems())

    def toBranch(self,branch,val):
        # convert a dc list into a tree of nested hashes
        if len(branch):
            x=branch.pop(0) # branch is modified by pop
            return {x:self.toBranch(branch,val)}
        else:
            return val

    def updateBranch(self,tree,branch):
        # tree is a nested hash of hashes, branch is a list of items
        #print "updating %s with %s" % (tree,branch)
        if type(tree) is int: # matched to a leaf
            if len(branch):
                tree=self.toBranch(branch,1)
            #tree['leaf']=1 # add the leaf
            return tree
        x=branch.pop(0) # branch is modified by pop
        if x in tree:
            tree[x]=self.updateBranch(tree[x],branch)
        else:
            tree[x]=self.toBranch(branch,1)
        return tree

    def countEntry(self,entry):
        try:
            dn=entry['dn'][0] if ',' in entry['dn'][0] or ('=' in entry['dn'][0] and '=' <> entry['dn'][0][-1]) else base64.b64decode(entry['dn'][0]) # guessing if it's base64
            treelist=re.split(r'(?<!\\),',dn.lower()) # split by , but not \,
            treelist.reverse()
            self.ldaptree=self.updateBranch(self.ldaptree,treelist);
        except:
            print "\nFailure processing %s\n%s, %s" % (entry,sys.exc_info()[0],sys.exc_info()[1])
            traceback.print_exc()
            sys.exit(2)

    def analyzeEntry(self,entry):
        filepattern=re.compile(r'[\\/:"*?<>|]+') # invalid filename characters on windows
        try:
            name=None
            data=None
            entryObjectclass=[o.lower() for o in entry['objectclass']]
            #if 'erWorkflowDefinition'.lower() in entryObjectclass and 'erxml' in entry: # Lifecycle workflows
            if 'erServiceProfile'.lower() in entryObjectclass: # service
                serviceprofilename=entry['ercustomclass'][0]
                serviceclass=entry['erserviceproviderfactory'][0] if 'erserviceproviderfactory' in entry else 'Native/DAML' # '''','.join(entry['erproperties'])
                self.serviceprofiles[serviceprofilename.lower()]=serviceclass
                #self.serviceprofiles[entry['dn'][0].lower()]=entry
                #self.serviceprofileskeys.update(dict(zip(entry.keys(),[1 for _ in entry.keys()])))
            elif 'erServiceItem'.lower() in entryObjectclass: # service
                servicetype=",".join([t for t in entryObjectclass if t != "erServiceItem".lower() and t != "top" and t != "erManagedItem".lower() and t != "erAccessItem".lower() and t != "erRemoteServiceItem".lower()])
                servicedn=entry['dn'][0].lower()
                serviceurl=entry['erurl'][0] if 'erurl' in entry else entry['host'][0] if 'host' in entry else entry['ersapnwlhostname'][0] if 'ersapnwlhostname' in entry else entry['eroraservicehost'][0] if 'eroraservicehost' in entry else ''
                serviceclass=self.serviceprofiles[servicetype] if servicetype in self.serviceprofiles else ''
                #print servicedn
                if servicedn not in self.services:
                    self.services[servicedn]={'name':entry["erservicename"][0],'type':servicetype,'url':serviceurl,'active accounts':0,'suspended accounts':0,'orphan accounts':0,'class':serviceclass}
                else: # overwrite the guessed name and service type, but keep the account counters
                    self.services[servicedn]['name']=entry["erservicename"][0]
                    self.services[servicedn]['type']=servicetype
                    self.services[servicedn]['url']=serviceurl
                    self.services[servicedn]['class']=serviceclass
            elif 'erAccountItem'.lower() in entryObjectclass: # service
                #accounttype="+".join([t for t in entry["objectclass"] if t != "erAccountItem" and t!="top" and t!="erManagedItem" and t!="erRemoteServiceItem"])
                #if accounttype not in self.accounts:
                #    self.accounts[accounttype]=1
                #else:
                #    self.accounts[accounttype]+=1
                #print >> self.drf, "Account "+entry["eruid"][0]+" type "+",".join([t for t in entry["objectclass"] if t != "erAccountItem" and t!="top" and t!="erManagedItem" and t!="erRemoteServiceItem"])
                #self.accounts[entry['dn'][0].lower()]=entry
                if 'erservice' not in entry:
                    print "Missing erservice in "+entry['eruid'][0]
                    return
                servicedn=entry['erservice'][0].lower()
                #if 'eraccountstatus' not in entry: # this is probably an orphan - ignore for now
                #    return # can further check if thats an oprhan by doing
                accountstatus=entry['eraccountstatus'][0] if 'eraccountstatus' in entry else ''
                if servicedn not in self.services: # we found an account before we found a serveice
                    serviceuid=re.search('erglobalid=(.+),ou=services',servicedn).group(1)
                    self.services[servicedn]={'name':serviceuid,'type':'unknown','url':'unknown','active accounts':0,'suspended accounts':0,'orphan accounts':0,'class':'unknown'}
                if "ou=orphans," in entry['dn'][0]:
                    self.services[servicedn]['orphan accounts']+=1
                elif accountstatus=='0': # active if 0, suspended if 1
                    self.services[servicedn]['active accounts']+=1
                else:
                    self.services[servicedn]['suspended accounts']+=1
            elif 'erProvisioningPolicy'.lower() in entryObjectclass: # Provisioinig Policies - ou=policies,erglobalid=00000000000000000000,ou=...
                #self.ppolicies[entry['dn'][0].lower()]=entry
                self.ppolicies[entry['dn'][0].lower()]={'name':entry["erpolicyitemname"][0],'members':entry["erpolicymembership"],'required':entry["erreqpolicytarget"] if 'erreqpolicytarget' in entry else None,'target':entry["erpolicytarget"] if 'erpolicytarget' in entry else None}
                ''' for erpolicymembership:

                    for erpolicytarget:
                    If a service instance is targeted, the value is the string representing the service instance's DN. Format: 1;<value>
                    If a service profile is targeted, the value is the name of the service profile. Format: 0;<value>
                    If all services are targeted, the value is * . Format: 2;<*>
                    If a service selection policy is targeted, the value is the name of the service profile affected by the service selection policy. Format: 3;<value>

                    erreqpolicytarget contains prerequisites in the same format
                '''
            elif 'erPersonItem'.lower() in entryObjectclass or 'erbppersonitem' in entryObjectclass: # person
                person={'name':entry['cn'][0], 'status':entry['erpersonstatus'][0],'roles':[]}
                if 'erroles' in entry:
                    person['roles']=[r.lower() for r in entry['erroles']]
                person['ou']=entry['erparent'][0].lower()
                person['class']=[o.lower() for o in entryObjectclass]#set([o.lower() for o in entryObjectclass])-set(['top','ermanageditem','inetorgperson','organizationalperson','person','erpersonitem'])
                person['attributes']=[k.lower() for k in entry.keys()]#set([k.lower() for k in entry.keys()])-set(['dn','cn','sn','displayname','ercreatedate','erglobalid','erparent','erpersonstatus','erlastmodifiedtime','erroles','ibm-entryuuid','control'])#[k.lower() for k in entry.keys()]
                person['num of attributes']=len(person['attributes'])
                self.people[entry['dn'][0].lower()]=person
            elif 'erRole'.lower() in entryObjectclass: # role
                self.roles[entry['dn'][0].lower()]={'name':entry['errolename'][0],'description':entry['description'][0] if 'description' in entry else '','members':0} # last item is a membership counter to be filled later
            elif 'erOrgUnitItem'.lower() in entryObjectclass or 'organizationalUnit'.lower() in entryObjectclass:
                self.ous[entry['dn'][0].lower()]={'name':entry['ou'][0],'parent':entry['erparent'][0].lower() if 'erparent' in entry else '','people':0}
            elif 'organization'.lower() in entryObjectclass:
                self.ous[entry['dn'][0].lower()]={'name':entry['o'][0],'parent':'','people':0}
            else:
                key=", ".join([o for o in sorted(entryObjectclass) if o <> "top" and o <> "ermanageditem"]) # a key to count all other object classes
                if key in self.other:
                    self.other[key]+=[entry['dn'][0]]
                else:
                    self.other[key]=[entry['dn'][0]]
            for o in entryObjectclass:
                self.objects[o]+=1
            dn=entry['dn'][0] if ',' in entry['dn'][0] or ('=' in entry['dn'][0] and '=' <> entry['dn'][0][-1]) else base64.b64decode(entry['dn'][0]) # guessing if it's base64
            #treelist=dn.lower().split(',')
            #print treelist
            treelist=re.split(r'(?<!\\),',dn.lower()) # split by , but not \,
            #print treelist
            treelist.reverse()
            #self.updateBranch(self.ldaptree,self.toBranch(treelist,1));
            self.ldaptree=self.updateBranch(self.ldaptree,treelist);
        except:
            print "\nFailure processing %s\n%s, %s" % (entry,sys.exc_info()[0],sys.exc_info()[1])
            traceback.print_exc()
            sys.exit(2)


if __name__ == '__main__':
    # reopen stdout file descriptor with write mode and 0 as the buffer size (unbuffered output)
    sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 0)
    if len(sys.argv) < 2:
        print __doc__
        sys.exit(1)
    filename=sys.argv[1] if len(sys.argv) == 2 else sys.argv[2]
    csvformat=True if sys.argv[1] == "-c" else False
    parser=LdifParser(filename,csvformat)
    parser.parseOut()
