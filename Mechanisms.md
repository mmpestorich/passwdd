The following mechanisms have been tested and are known to fully work:
  * DIGEST-MD5 (AFP, su)
  * CRAM-MD5
  * DHX
  * MS-CHAPv2

These mechanisms are known to at-least partially work (more testing is needed):
  * WEBDAV-DIGEST
    * Works with: Wiki, Collaboration Services, Address Book, iCal, iChat
    * Does NOT work with: ??
    * Untested: ??

These mechanisms have not been fully tested yet (frankly they may never be used):
  * SMB-NTLMv2
  * SMB-NT
  * SMB-LAN-MANAGER
  * PPS
  * OTP
  * GSSAPI
  * APOP