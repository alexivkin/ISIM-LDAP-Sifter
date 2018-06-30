#!/usr/bin/python
'''
Go over an ldap extract and convert it from PBEWithMD5AndDES to AES (AES/ECB/PKCS5Padding)

the password is either in enRole.properties as enrole.encryption.password or inside encryptionKey.properties as encryption.password
you can get the password from {ITIM}/data/keystore/itimKeystore.jceks using JCEKStractor from the ITIM Crypto Seer repo

reencrypter.py [-x] <name of the ldif> <PBE encryption password> <AES encryption key>

<AES encryption key> should be base64 encoded. It comes from a JCEKS key store. You will need to extract it first with JCEKStractor

-x will cause it to check if the key is already correctly encrypted and thus should not be touched. Warning - it may cause false positives, for example in the case where last byte of the decrypted value (padding) is 1

Saves to <name of the ldif>-rec to use with ldif2db and -mod to use with ldapmodify, depending on what you prefer

Requires Pycrypto that you could install with
yum install python-crypto
apt install python-crypto

2012-2017
@author: Alex Ivkin

'''
from __future__ import print_function
import base64,sys,os,subprocess,math,re
from Crypto.Hash import MD5,SHA256
from Crypto.Cipher import DES,AES

# default encrypted attributes
encryptedAttributes=["erpassword"]
# "erhistoricalpassword" - contains a one-way hash and a (possibly) a reverse of that hash, base64 encoded and not (easily) recoverable
# grep password.attributes /opt/IBM/isim/data/enRole.properties + erpassword
encryptedAttributes.extend(["ersynchpassword","erServicePassword","erServicePwd1","erServicePwd2","erServicePwd3","erServicePwd4","erADDomainPassword","erPersonPassword","erNotesPasswdAddCert","eritamcred","erep6umds","erposixpassphrase"])

class LdifParser:

    def __init__(self,filename,decryptpass,encryptkey,testWithNewKey=False,debug=False):
        salt = "\xC7\x73\x21\x8C\x7E\xC8\xEE\x99" # magic
        iterations=20
        self.blocksize=16
        self.ldif=filename
        self.key, self.iv = self.compute_DES_key_iv(decryptpass, salt, iterations)
        self.encoder = AES.new(encryptkey, AES.MODE_ECB)
        self.testWithNewKey=testWithNewKey
        #self.autogen=re.compile(r'(?=.*?[a-z])(?=.*?[A-Z])(?=.*?[^a-zA-Z]).{8,}') # Minimum eight characters, at least one uppercase letter, one lowercase letter and one number:
        self.autogen=re.compile(r'(?=.*?[a-z].*[a-z])(?=.*?[A-Z].*[A-Z])(?=.*?[0-9].*[0-9]).{8,}') # eight char, two of each
        self.alphanumchar=re.compile(r'^[A-Za-z0-9"~`!@#$%^&*()_+={}:>;\'.,</?*"\[\]\-\|\\/ ]*$')
        self.debug=debug

    def parseOut(self):
        i=0
        last=-1
        invalid=0
        oneway=0
        skipped=0
        encryptedcount=0
        encryptedAttributesTuple=tuple([e.lower()+":" for e in encryptedAttributes])
        if debug:
            self.debugf=open(self.ldif+".debug","w")
        recfname=os.path.splitext(self.ldif)[0]+"-rec"+os.path.splitext(self.ldif)[1]
        delfname=os.path.splitext(self.ldif)[0]+"-mod"+os.path.splitext(self.ldif)[1]
        with open(self.ldif,"r") as inf, open(recfname,"w") as outf, open(delfname,"w") as outmodf:
            print("Opening...",end="")
            # fastest line count using wc
            p = subprocess.Popen(['wc', '-l', self.ldif], stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            result, err = p.communicate()
            if p.returncode != 0:
                raise IOError(err)
            num_lines=int(result.strip().split()[0]) # 118593960
            print("%s lines." % num_lines)
            encryptedAttr=False
            continuedAttr=False
            for line in inf:
                if line.lower().startswith("dn:"):
                    self.currentdn=line.rstrip(' \n\r')
                if encryptedAttr: # previously saw an encrypted attribute
                    if line.startswith(" "): # continuation
                        val+=line.strip()
                        continuedAttr=True
                    else: # decode and write
                        newline=attr+": "+val+"\n" # assume by default we're keeping it as is
                        if val.startswith("MD5:") or val.startswith("SHA-256:"):
                            oneway+=1
                            if debug:
                                self.debugf.write(self.currentdn+" =| "+val+"\n")
                        else:
                            try:
                                newval = self.reencrypt(val)
                                #except KeyboardInterrupt:
                                #    print("Aborted")
                                #    sys.exit(99)
                            except:      # if could not decrypt
                                try:
                                    newval = self.reencrypt(base64.b64decode(val)) # some attributes could be a double base64 encoded. Try it again.
                                    newval = base64.b64encode(newval) # double base64 decoding worked - recode back with the additional base 64
                                #except KeyboardInterrupt:
                                #    print("Aborted")
                                #    sys.exit(99)
                                except:
                                    #print("%s: %s on %s" % (sys.exc_info()[0],sys.exc_info()[1],val))
                                    newval = None
                            if newval == None and self.testWithNewKey: # # cant re-encrypt. check if it's already correctly encrypted, i.e. has been re-encrypted before
                                try:
                                    newval=self.unpad(self.encoder.decrypt(base64.b64decode(val))) # may occasionally cause a false positive - e.g. last byte/padding is 1
                                    skipped+=1  # no need to reencrypt
                                    if debug:
                                        self.debugf.write(self.currentdn+" =! "+newval+"\n")
                                except: # test for new encryption failed
                                    newval = None
                            if newval == None: # still no luck
                                invalid+=1
                                if debug:
                                    self.debugf.write(self.currentdn+" =? "+val+"\n")
                                outmodf.write("# invalid encoding\n")
                                outmodf.write(self.currentdn+"\n")
                                outmodf.write("changetype: modify\n")
                                outmodf.write("delete: "+attr+"\n")
                                outmodf.write(line) # this line is needed in case there are multiple attribute values. It also helps identify bad encryption values.
                                outmodf.write("\n")
                            else:
                                newline=attr+": "+newval+"\n" # reencrypted value
                                outmodf.write("# reencoded\n")
                                outmodf.write(self.currentdn+"\n")
                                outmodf.write("changetype: modify\n")
                                outmodf.write("replace: "+attr+"\n")
                                outmodf.write(line)
                                outmodf.write("\n")
                                #self.debugf.write(attr)
                        encryptedcount+=1
                        encryptedAttr=False
                        continuedAttr=False
                        outf.write(newline) # write out and continue
                        #print("Writing out "+newline)
                if not continuedAttr:
                    if line.lower().startswith(encryptedAttributesTuple):
                        attr= line.split(":",1)[0].strip()
                        val = line.split(":",1)[1][1:].strip()
                        encryptedAttr=len(val)>0 # sometimes encrypted values are empty so we just skip it
                        #print("Encrypted "+line)
                    else:
                        encryptedAttr=False
                        outf.write(line)
                #if debug and line.lower().startswith(('eruid','cn')):
                #    self.debugf.write(line)
                # show progress
                percent = math.ceil(i/float(num_lines)*100*1000)/1000 # round to the tenth of a percent
                if percent > last :# cant simply use modulus because of the freaky float imprecision
                    sys.stdout.write('\rParsing %s: %s' % (self.ldif, "{:>5.1f}%".format(percent)))
                    last=percent
                i+=1
        print(" done.\nSaved to %s and %s" %(recfname,delfname))
        if encryptedcount == 0:
            print("No changes")
            os.unlink(outf.name)
            if debug:
                os.unlink(self.debugf.name)
        else:
            print("%s encrypted values found, %s reencrypted, %s skipped (already with new encryption), %s invalid, %s one way hashed." % (encryptedcount,encryptedcount-invalid-skipped-oneway,skipped,invalid,oneway))

        #except:
        #    print "\nFailure processing %s\n%s, %s" % (entry,sys.exc_info()[0],sys.exc_info()[1])
        #    traceback.print_exc()
        #    sys.exit(2)

    def reencrypt(self, data):
        try:
            self.decoder = DES.new(self.key, DES.MODE_CBC, self.iv) # need to reinit it each time because of CBC
            decrypted=self.unpad(self.decoder.decrypt(base64.b64decode(data)))
            if debug:
                if len(decrypted)==8 and re.match(self.autogen,decrypted) is not None:
                    self.debugf.write(self.currentdn+" =* "+decrypted+"\n")
                elif re.match(self.alphanumchar,decrypted) is not None:
                    self.debugf.write(self.currentdn+" => "+decrypted+"\n")
                else:
                    self.debugf.write(self.currentdn+" =x "+decrypted+"\n")
            encrypted=self.encoder.encrypt(self.pad(decrypted))
            newdata=base64.b64encode(encrypted)
            return newdata
        except:
            raise

    def compute_DES_key_iv(self,password, salt, iterations=20):
        hasher = MD5.new()
        hasher.update(password)
        hasher.update(salt)
        result = hasher.digest()
        for i in xrange(1, iterations):
            hasher = MD5.new()
            hasher.update(result)
            result = hasher.digest()
        return result[:8], result[8:16]

    def unpad(self,text): # pkcs7
        pad_val = ord(text[-1])
        pos = len(text) - pad_val
        if pad_val == 0 or text[-pad_val:] != chr(pad_val) * pad_val:
            raise ValueError("Invalid padding")
        return text[:pos]

    def pad(self,s): # per standard PKCS#5 is padding to blocksize 8, PKCS#7 is for any block size 1 to 255
        return s + (self.blocksize - len(s) % self.blocksize) * chr(self.blocksize - len(s) % self.blocksize)

if __name__ == '__main__':
    sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 0)
    if len(sys.argv)<4:
        print (__doc__)
        sys.exit(1)
    debug=False
    crosstest=False
    if sys.argv[1] == "-d":
        sys.argv.pop(0)
        debug=True
    if sys.argv[1] == "-x":
        sys.argv.pop(0)
        crosstest=True
    try:
        encryptkey=base64.b64decode(sys.argv[3])
    except TypeError:
        print("TypeError: %s on %s.\nIs this a valid base64 encoded encryption key?" % (sys.exc_info()[1],sys.argv[3]))
        sys.exit(2)
    parser=LdifParser(sys.argv[1],sys.argv[2],encryptkey,testWithNewKey=crosstest, debug=debug)
    parser.parseOut()
 