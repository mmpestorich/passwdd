# GETGLOBALPOLICY #

Retrieve the global password policy for the entire system.

## Sample ##

GETGLOBALPOLICY

+OK usingHistory=0 canModifyPasswordforSelf=1 usingExpirationDate=0 usingHardExpirationDate=0 requiresAlpha=1 requiresNumeric=1 expirationDateGMT=18446744073709551615 hardExpireDateGMT=18446744073709551615 maxMinutesUntilChangePassword=0 maxMinutesUntilDisabled=0 maxMinutesOfNonUse=0 maxFailedLoginAttempts=0 minChars=6 maxChars=0 passwordCannotBeName=1 requiresMixedCase=0 requiresSymbol=0 newPasswordRequired=0 minutesUntilFailedLoginReset=0 notGuessablePattern=0

# GETPOLICY #

Retrieve the password policy for a specific user. If used with the optional ACTUAL 2nd parameter it retrieves a merged result set of the global password policy and the users password policy.

## Sample ##

GETPOLICY 0x49d16f370c27351f0000000d0000000d

+OK isDisabled=0 isAdminUser=0 newPasswordRequired=0 usingHistory=0 canModifyPasswordforSelf=1 usingExpirationDate=0 usingHardExpirationDate=0 requiresAlpha=0 requiresNumeric=0 expirationDateGMT=18446744073709551615 hardExpireDateGMT=18446744073709551615 maxMinutesUntilChangePassword=0 maxMinutesUntilDisabled=0 maxMinutesOfNonUse=0 maxFailedLoginAttempts=0 minChars=0 maxChars=0 passwordCannotBeName=0 requiresMixedCase=0 requiresSymbol=0 notGuessablePattern=0 isSessionKeyAgent=0 isComputerAccount=0 adminClass=0 adminNoChangePasswords=0 adminNoSetPolicies=0 adminNoCreate=0 adminNoDelete=0 adminNoClearState=0 adminNoPromoteAdmins=0

## Sample2 ##

GETPOLICY 0x49d16f370c27351f0000000d0000000d ACTUAL

+OK isDisabled=0 isAdminUser=0 newPasswordRequired=0 usingHistory=0 canModifyPasswordforSelf=1 usingExpirationDate=0 usingHardExpirationDate=0 requiresAlpha=1 requiresNumeric=1 expirationDateGMT=18446744073709551615 hardExpireDateGMT=18446744073709551615 maxMinutesUntilChangePassword=0 maxMinutesUntilDisabled=0 maxMinutesOfNonUse=0 maxFailedLoginAttempts=0 minChars=6 maxChars=0 passwordCannotBeName=1 isSessionKeyAgent=0 requiresMixedCase=0 requiresSymbol=0 notGuessablePattern=0 adminClass=0 adminNoChangePasswords=0 adminNoSetPolicies=0 adminNoCreate=0 adminNoDelete=0 adminNoClearState=0 adminNoPromoteAdmins=0 logOffTime=0 kickOffTime=0 lastLoginTime=1356384272 passwordLastSetTime=1238462263