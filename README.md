# ISIM Data tools

Various ISIM data processing tools useful for upgrades, backups, cleanup, performance tuning and encryption changes.

* Extract ISIM code from an LDAP export into XMLs and CSVs - `codeextractor.py`. The extracted code can be used for change control and data visualization (see [ISIM Workflow Reporter](Automatic-ISIM-Workflow-Documentation))
	* Global Workflows
	* Category(Operational) Workflow
	* ProvisioningPolicies'
	* AssemblyLines
	* Forms
	* Mail Templates
	* ACLs

* Extract ISIM data in LDIF format - `dataextractor.py`. This is an intellegent LDIF dump splitter. Resulting LDIFs can be reimported back. This is also useful for data shuffling and creating Prod data subsets for safely using in other environments
	* ACLs
	* Services
	* People records
	* Tenant configuration - erglobalid=00000000000000000000,ou=[name],dc=com:
	* ITIM Configuration - ou=itim,ou=[name],DC=COM
	* Custom data - ou=data,ou=[name],dc=com

* Analyzing ISIM data - `inspector.py`. Creates sorted summary tables of many ISIM configuration data points
	* OUs
	* Provisioning policies, including applicable roles and services
	* Roles, including types and number of people with these roles
	* Services, including types, endpoints and number of accounts
	* LDAP Tree with number of subentries
	* And much more

* Reencrypting ISIM passwords - `reencrypter.py`. Goes over existing encrypted entries, decodes and reencodes them with different encryption keys, saves it into another LDIF.
	* Useful for upgrades or moving data between environments that do not have their cryptography synchronized.
	* This is an "automation" script. For individual password encryption/decryption see the LDAP Crypto Seer repo
	* Converts PBE/MD5/DES to AES/ECB/PKCS5Padding (default TIM 5.x to SIM 6 encryption). Oracle JDK 6 and 7 use AES/ECB/PKCS5Padding when only 'AES' is specified.
	* The attributes that it reencodes are:
		* erpassword
		* ersynchpassword
		* erServicePassword
		* erServicePwd1,erServicePwd2,erServicePwd3,erServicePwd4
		* erADDomainPassword
		* erPersonPassword
		* erNotesPasswdAddCert
		* eritamcred
		* erep6umds
		* erposixpassphrase

## Setup

For the tools to work you first need to dump your exsisting ISIM LDAP into an LDIF format. You can do it in one of the following ways:

* (preferred) Dump the whole ISIM LDAP in an LDIF format
	/opt/IBM/ldap/[version]/sbin/db2ldif -o /tmp/ldapdump.ldif
This file can get big, but it compresses well.

* Use ldapsearch to export specific subtrees
```
ldapsearch -h host -D cn=admin -w password -s sub (objectclass=erServiceItem) > ldapexport-services.ldif
ldapsearch -h host -D cn=admin -w password -s sub (objectclass=erProvisioningPolicy) > ldapexport-pp.ldif
ldapsearch -h host -D cn=admin -w password -s sub (objectclass=erWorkflowDefinition) > ldapexport-workflows.ldif
ldapsearch -h host -D cn=admin -w password -s sub (objectclass=erRole) > ldapexport-roles.ldif
ldapsearch -h host -D cn=admin -w password -s sub (objectclass=*) -b ou=itim,ou=[company],dc=itim,dc=dom > ldapexport-conf.ldif
```
This limits the size of the export, but will miss some details - for example all the non-ascii (binary or utf) values will be lost.

The last ldapsearch includes erServiceProfile, erObjectCategory from ou=category,ou=itim,ou=[company],dc=itim,dc=dom,  erTemplate from ou=config,ou=itim,ou=[company],dc=itim,dc=dom, erFormTemplate from ou=formTemplates,ou=itim,ou=[company],dc=itim,dc=dom and many others.

* Use your preferred LDAP browser's (Apache Directory Studio recommended) export ability to save the following
```
(objectclass=erServiceItem) from ou=services,erglobalid=00000000000000000000,ou=[company],dc=itim,dc=dom
(objectclass=erProvisioningPolicy) from ou=policies,erglobalid=00000000000000000000,ou=[company],dc=itim,dc=dom
(objectclass=erWorkflowDefinition) from ou=workflow,erglobalid=00000000000000000000,ou=[company],dc=itim,dc=dom
(objectclass=erRole) from ou=roles,erglobalid=00000000000000000000,ou=[company],dc=itim,dc=dom
(objectclass=*) from ou=itim,ou=[company],dc=itim,dc=dom
```
dc=itim,dc=dom is a root suffix and may be different depending on how ITIM was set up initially

## Usage

### Extract ISIM javascript code, workflows, provisioning policies, ACIs etc - codeextractor.py
Extract ITIM configuration components from an LDIF into readable (base64 decoded) XML files. Provide the name of the ldif, exported per directions above. Creates subfolders in the same folder with the exported components.

### Understand ISIM configuration - inspector.py
Analyzes LDIF and produces many stats and an LDAP tree overview. Uses a bunch of memory, close to the size of the original ldif.
```inspector.py [-c] <name of the ldif>```
 -c to output stats as csv files

Needs PrettyTable
```sudo apt-get install python-prettytable```

### Split out data in subfiles - dataextractor.py
Useful for converting Prod data to a subset that is safe and confidential for importing into Dev and QA.
```dataextractor.py [-a][-d] <name of the ldif>```
 -a to extract all data. If no -a is supplied the data is truncated and modified for non-Prod environments. E.g only 10 random people are exported, services are disabled by modifying erurl, service supporting data (groups etc) is skipped.
 -d to create removal ldifs, so data can be replaced. It uses DNs from the input LDIF. The side effect is that any DNs that are in the LDAP, but not in input LDIF will not be removed.
   To clean all of the existing entries run dataextractor on the ldapdump from the current LDAP or just use the build-cleaner-from-ldif.sh script

This code assumes the base DN is dn=com. Recycle bin is always skipped.

### Convert TIM 5.x encryption to SIM 6/7 encryption - reencrypter.py
Go over an ldap extract and convert it from PBEWithMD5AndDES to AES (AES/ECB/PKCS5Padding).
```reencrypter.py [-x] <name of the ldif> <PBE encryption password> <AES encryption key>```

`<PBE encryption password>` is the TIM 5.x password, either from enRole.properties as enrole.encryption.password or inside encryptionKey.properties as encryption.password.

`<AES encryption key>` is the SIM 6 binary encryption key. It comes from a JCEKS key store. You might need to extract it first from {ITIM}/data/keystore/itimKeystore.jceks using JCEKStractor from the ITIM Crypto Seer repo. It should be base64 encoded.

-x will cause it to check if the key is already correctly encrypted and thus should not be re-encrypted. Warning - it may cause false positives, for example in the case where last byte of the decrypted value (padding) is 1

Saves to `<name of the ldif>-rec.ldif` to use with ldif2db and `<name of the ldif>-mod.ldif>` to use with ldapmodify, depending on what you prefer.

Requires Pycrypto that you could install with
apt install python-crypto
