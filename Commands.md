## Implemented commands ##

These are the commands that are known to work so far:
  * LIST - Lists available mechanisms.
  * RSAPUBLIC - Retrieve the public RSA key for this server.
  * RSAVALIDATE - Client sends us encrypted data and we send it back cleartext.
  * USER - specify username to authenticate as.
  * AUTH - Step 1 authentication.
  * AUTH2 - Step 2 authentication (if required by mechanism, most do).
  * NEWUSER - Creates a new user in the password database.
  * CHANGEPASS - Changes the password of a user.
  * DELETEUSER - Deletes a user from the password database.
  * QUIT - Logoff.

## Stub commands ##
  * GETPOLICY

## Not implemented commands (partial list) ##
  * SETPOLICY