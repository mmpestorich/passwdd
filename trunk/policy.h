/*
Copyright (C) 2012 Daniel Hazelbaker  

Permission is hereby granted, free of charge, to any person obtaining a
copy of this software and associated documentation files (the "Software"),
to deal in the Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included
in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
*/

#ifndef __POLICY_H__
#define __POLICY_H__

#include <stdint.h>


extern const char *kPolicyUsingHistory;
extern const char *kPolicyCanModifyPasswordForSelf;
extern const char *kPolicyUsingExpirationDate;
extern const char *kPolicyUsingHardExpirationDate;
extern const char *kPolicyRequiresAlpha;
extern const char *kPolicyRequiresNumeric;
extern const char *kPolicyPasswordCannotBeName;
extern const char *kPolicyRequiresMixedCase;
extern const char *kPolicyRequiresSymbol;
extern const char *kPolicyNewPasswordRequired;
extern const char *kPolicyNotGuessablePattern;

extern const char *kPolicyExpirationDateGMT;
extern const char *kPolicyHardExpireDateGMT;
extern const char *kPolicyMaxMinutesUntilChangePassword;
extern const char *kPolicyMaxMinutesUntilDisabled;
extern const char *kPolicyMaxMinutesOfNonUse;
extern const char *kPolicyMaxFailedLoginAttempts;
extern const char *kPolicyMinChars;
extern const char *kPolicyMaxChars;
extern const char *kPolicyMinutesUntilFailedLoginReset;

extern const char *kPolicyIsDisabled;
extern const char *kPolicyIsAdminUser;
extern const char *kPolicyIsSessionKeyAgent;
extern const char *kPolicyIsComputerAccount;
extern const char *kPolicyAdminClass;
extern const char *kPolicyAdminNoChangePasswords;
extern const char *kPolicyAdminNoSetPolicies;
extern const char *kPolicyAdminNoCreate;
extern const char *kPolicyAdminNoDelete;
extern const char *kPolicyAdminNoClearState;
extern const char *kPolicyAdminNoPromoteAdmins;
extern const char *kPolicyLogOffTime;
extern const char *kPolicyKickOffTime;
extern const char *kPolicyLastLoginTime;
extern const char *kPolicyPasswordLastSetTime;

typedef struct gPasswordPolicy {
    unsigned usingHistory : 1;
    unsigned canModifyPasswordForSelf : 1;
    unsigned usingExpirationDate : 1;
    unsigned usingHardExpirationDate : 1;
    unsigned requiresAlpha : 1;
    unsigned requiresNumeric : 1;
    unsigned passwordCannotBeName : 1;
    unsigned requiresMixedCase : 1;
    unsigned requiresSymbol : 1;
    unsigned newPasswordRequired : 1;
    unsigned notGuessablePattern : 1;

    uint64_t expirationDateGMT;
    uint64_t hardExpireDateGMT;
    uint64_t maxMinutesUntilChangePassword;
    uint64_t maxMinutesUntilDisabled;
    uint64_t maxMinutesOfNonUse;
    uint64_t maxFailedLoginAttempts;
    uint64_t minChars;
    uint64_t maxChars;
    uint64_t minutesUntilFailedLoginReset;

    /* User policy */
    unsigned isDisabled : 1;
    unsigned isAdminUser : 1;
    unsigned isSessionKeyAgent : 1;
    unsigned isComputerAccount : 1;
    unsigned adminClass : 1;
    unsigned adminNoChangePasswords : 1;
    unsigned adminNoSetPolicies : 1;
    unsigned adminNoCreate : 1;
    unsigned adminNoDelete : 1;
    unsigned adminNoClearState : 1;
    unsigned adminNoPromoteAdmins : 1;

    uint64_t logOffTime;
    uint64_t kickOffTime;
    uint64_t lastLoginTime;
    uint64_t passwordLastSetTime;
} aPasswordPolicy;


aPasswordPolicy	*policy_new(const char *policy_string);
void		policy_delete(aPasswordPolicy *policy);
int		policy_parse(aPasswordPolicy *policy,
			     const char *policy_string);
int		policy_to_string(aPasswordPolicy *policy,
				 char *string, int string_max, int isUser);

#endif /* __POLICY_H__ */
