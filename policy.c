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

#include <stdio.h>
#include <string.h>
#include <errno.h>
#ifdef HAVE_MALLOC_H
#include <malloc.h>
#endif
#include <stdlib.h>
#include "policy.h"
#include "common.h"
#include "conf.h"
#include "utils.h"


const char *kPolicyUsingHistory = "usingHistory";
const char *kPolicyCanModifyPasswordForSelf = "canModifyPasswordforSelf";
const char *kPolicyUsingExpirationDate = "usingExpirationDate";
const char *kPolicyUsingHardExpirationDate = "usingHardExpirationDate";
const char *kPolicyRequiresAlpha = "requiresAlpha";
const char *kPolicyRequiresNumeric = "requiresNumeric";
const char *kPolicyPasswordCannotBeName = "passwordCannotBeName";
const char *kPolicyRequiresMixedCase = "requiresMixedCase";
const char *kPolicyRequiresSymbol = "requiresSymbol";
const char *kPolicyNewPasswordRequired = "newPasswordRequired";
const char *kPolicyNotGuessablePattern = "notGuessablePattern";

const char *kPolicyExpirationDateGMT = "expirationDateGMT";
const char *kPolicyHardExpireDateGMT = "hardExpireDateGMT";
const char *kPolicyMaxMinutesUntilChangePassword = "maxMinutesUntilChangePassword";
const char *kPolicyMaxMinutesUntilDisabled = "maxMinutesUntilDisabled";
const char *kPolicyMaxMinutesOfNonUse = "maxMinutesOfNonUse";
const char *kPolicyMaxFailedLoginAttempts = "maxFailedLoginAttempts";
const char *kPolicyMinChars = "minChars";
const char *kPolicyMaxChars = "maxChars";
const char *kPolicyMinutesUntilFailedLoginReset = "minutesUntilFailedLoginReset";

const char *kPolicyIsDisabled = "isDisabled";
const char *kPolicyIsAdminUser = "isAdminUser";
const char *kPolicyIsSessionKeyAgent = "isSessionKeyAgent";
const char *kPolicyIsComputerAccount = "isComputerAccount";
const char *kPolicyAdminClass = "adminClass";
const char *kPolicyAdminNoChangePasswords = "adminNoChangePasswords";
const char *kPolicyAdminNoSetPolicies = "adminNoSetPolicies";
const char *kPolicyAdminNoCreate = "adminNoCreate";
const char *kPolicyAdminNoDelete = "adminNoDelete";
const char *kPolicyAdminNoClearState = "adminNoClearState";
const char *kPolicyAdminNoPromoteAdmins = "adminNoPromoteAdmins";
const char *kPolicyLogOffTime = "logOffTime";
const char *kPolicyKickOffTime = "kickOffTime";
const char *kPolicyLastLoginTime = "lastLoginTime";
const char *kPolicyPasswordLastSetTime = "passwordLastSetTime";



static int	policy_parse_item(aPasswordPolicy *policy,
				  char *key, char *value);


//
// Allocate a new password policy structure, optionally filling it with
// the information from the policy_string if set. Pass NULL to initialize
// an empty policy.
//
aPasswordPolicy	*policy_new(const char *policy_string)
{
    aPasswordPolicy	*policy;


    //
    // Allocate and zero out the policy.
    //
    policy = (aPasswordPolicy *)malloc(sizeof(aPasswordPolicy));
    memset(policy, 0, sizeof(aPasswordPolicy));
    policy->expirationDateGMT = UINT64_MAX;
    policy->hardExpireDateGMT = UINT64_MAX;

    //
    // If they passed in a policy string, parse it.
    //
    if (policy_string != NULL) {
        if (policy_parse(policy, policy_string) != 0) {
            free(policy);
            return NULL;
        }
    }

    return policy;
}


//
// Free memory used by the given password policy.
//
void		policy_delete(aPasswordPolicy *policy)
{
    free(policy);
}


//
// Parse the given policy string into the password policy structure. If
// the policy string is not valid then return a non-zero integer. If
// everything was parsed correctly then returns 0.
//
int		policy_parse(aPasswordPolicy *policy,
			     const char *policy_string)
{
    const char *ws, *p;
    char item[POLICY_MAX], *key, *value;
    int len, ret;


    for (p = policy_string; *p != '\0'; p = ws) {
        //
        // Find the end of this policy item.
        //
        while (*p == ' ')
            p++;
        for (ws = p; *ws != ' ' && *ws != '\0'; ws++)
            ;

        //
        // Copy the string to a mutable buffer.
        //
        len = (int)(ws - p);
        if (len >= POLICY_MAX)
            return -E2BIG;
        memcpy(item, p, len);
        item[len] = '\0';

        //
        // Find the equal sign in this item.
        //
        key = item;
        value = strchr(key, '=');
        if (value == NULL)
            return -EINVAL;
        *value++ = '\0';

        //
        // Parse the single policy item.
        //
        ret = policy_parse_item(policy, key, value);
        if (ret != 0)
            return ret;
    }

    return 0;
}


//
// Parse a single policy item entry into the policy structure. Returns
// 0 on success or a negative value to indicate an error.
//
static int	policy_parse_item(aPasswordPolicy *policy,
				  char *key, char *value)
{
    if (strcmp(key, kPolicyUsingHistory) == 0) {
        policy->usingHistory = (*value == '1');
    }
    else if (strcmp(key, kPolicyCanModifyPasswordForSelf) == 0) {
        policy->canModifyPasswordForSelf = (*value == '1');
    }
    else if (strcmp(key, kPolicyUsingExpirationDate) == 0) {
        policy->usingExpirationDate = (*value == '1');
    }
    else if (strcmp(key, kPolicyUsingHardExpirationDate) == 0) {
        policy->usingHardExpirationDate = (*value == '1');
    }
    else if (strcmp(key, kPolicyRequiresAlpha) == 0) {
        policy->requiresAlpha = (*value == '1');
    }
    else if (strcmp(key, kPolicyRequiresNumeric) == 0) {
        policy->requiresNumeric = (*value == '1');
    }
    else if (strcmp(key, kPolicyPasswordCannotBeName) == 0) {
        policy->passwordCannotBeName = (*value == '1');
    }
    else if (strcmp(key, kPolicyRequiresMixedCase) == 0) {
        policy->requiresMixedCase = (*value == '1');
    }
    else if (strcmp(key, kPolicyRequiresSymbol) == 0) {
        policy->requiresSymbol = (*value == '1');
    }
    else if (strcmp(key, kPolicyNewPasswordRequired) == 0) {
        policy->newPasswordRequired = (*value == '1');
    }
    else if (strcmp(key, kPolicyNotGuessablePattern) == 0) {
        policy->notGuessablePattern = (*value == '1');
    }
    else if (strcmp(key, kPolicyExpirationDateGMT) == 0) {
        policy->expirationDateGMT = strtoull(value, NULL, 10);
    }
    else if (strcmp(key, kPolicyHardExpireDateGMT) == 0) {
        policy->hardExpireDateGMT = strtoull(value, NULL, 10);
    }
    else if (strcmp(key, kPolicyMaxMinutesUntilChangePassword) == 0) {
        policy->maxMinutesUntilChangePassword = strtoull(value, NULL, 10);
    }
    else if (strcmp(key, kPolicyMaxMinutesUntilDisabled) == 0) {
        policy->maxMinutesUntilDisabled = strtoull(value, NULL, 10);
    }
    else if (strcmp(key, kPolicyMaxMinutesOfNonUse) == 0) {
        policy->maxMinutesOfNonUse = strtoull(value, NULL, 10);
    }
    else if (strcmp(key, kPolicyMaxFailedLoginAttempts) == 0) {
        policy->maxFailedLoginAttempts = strtoull(value, NULL, 10);
    }
    else if (strcmp(key, kPolicyMinChars) == 0) {
        policy->minChars = strtoull(value, NULL, 10);
    }
    else if (strcmp(key, kPolicyMaxChars) == 0) {
        policy->maxChars = strtoull(value, NULL, 10);
    }
    else if (strcmp(key, kPolicyMinutesUntilFailedLoginReset) == 0) {
        policy->minutesUntilFailedLoginReset = strtoull(value, NULL, 10);
    }
    else if (strcmp(key, kPolicyIsDisabled) == 0) {
        policy->isDisabled = (*value == '1');
    }
    else if (strcmp(key, kPolicyIsAdminUser) == 0) {
        policy->isAdminUser = (*value == '1');
    }
    else if (strcmp(key, kPolicyIsSessionKeyAgent) == 0) {
        policy->isSessionKeyAgent = (*value == '1');
    }
    else if (strcmp(key, kPolicyIsComputerAccount) == 0) {
        policy->isComputerAccount = (*value == '1');
    }
    else if (strcmp(key, kPolicyAdminClass) == 0) {
        policy->adminClass = (*value == '1');
    }
    else if (strcmp(key, kPolicyAdminNoChangePasswords) == 0) {
        policy->adminNoChangePasswords = (*value == '1');
    }
    else if (strcmp(key, kPolicyAdminNoSetPolicies) == 0) {
        policy->adminNoSetPolicies = (*value == '1');
    }
    else if (strcmp(key, kPolicyAdminNoCreate) == 0) {
        policy->adminNoCreate = (*value == '1');
    }
    else if (strcmp(key, kPolicyAdminNoDelete) == 0) {
        policy->adminNoDelete = (*value == '1');
    }
    else if (strcmp(key, kPolicyAdminNoClearState) == 0) {
        policy->adminNoClearState = (*value == '1');
    }
    else if (strcmp(key, kPolicyAdminNoPromoteAdmins) == 0) {
        policy->adminNoPromoteAdmins = (*value == '1');
    }
    else if (strcmp(key, kPolicyLogOffTime) == 0) {
        policy->logOffTime = strtoull(value, NULL, 10);
    }
    else if (strcmp(key, kPolicyKickOffTime) == 0) {
        policy->kickOffTime = strtoull(value, NULL, 10);
    }
    else if (strcmp(key, kPolicyLastLoginTime) == 0) {
        policy->lastLoginTime = strtoull(value, NULL, 10);
    }
    else if (strcmp(key, kPolicyPasswordLastSetTime) == 0) {
        policy->passwordLastSetTime = strtoull(value, NULL, 10);
    }
    else {
        printf("Could not find policy key %s\r\n", key);
        return -ENOENT;
    }

    return 0;
}


//
// Convert the password policy into a string representation. The string
// is stored in the string parameter, whose string_max size must be big
// enough to store the representation. If the isUser parameter is set
// then the user-version of the password policy is returned, otherwise
// those extra fields are ignored and the Global Password Policy is
// stored. Returns 0 on success.
//
int		policy_to_string(aPasswordPolicy *policy,
				 char *string, int string_max, int isUser)
{
    int len = 0;


    if (policy == NULL || string == NULL || string_max <= 0)
        return -EINVAL;

    //
    // Prepare the string.
    //
    *string = '\0';

    //
    // Put in all the global policy options.
    //
    len += snprintfcat(string, string_max, "%s=%d ",
		kPolicyUsingHistory,
		policy->usingHistory);
    len += snprintfcat(string, string_max, "%s=%d ",
		kPolicyCanModifyPasswordForSelf,
		policy->canModifyPasswordForSelf);
    len += snprintfcat(string, string_max, "%s=%d ",
		kPolicyUsingExpirationDate,
		policy->usingExpirationDate);
    len += snprintfcat(string, string_max, "%s=%d ",
		kPolicyUsingHardExpirationDate,
		policy->usingHardExpirationDate);
    len += snprintfcat(string, string_max, "%s=%d ",
		kPolicyRequiresAlpha,
		policy->requiresAlpha);
    len += snprintfcat(string, string_max, "%s=%d ",
		kPolicyRequiresNumeric,
		policy->requiresNumeric);
    len += snprintfcat(string, string_max, "%s=%d ",
		kPolicyPasswordCannotBeName,
		policy->passwordCannotBeName);
    len += snprintfcat(string, string_max, "%s=%d ",
		kPolicyRequiresMixedCase,
		policy->requiresMixedCase);
    len += snprintfcat(string, string_max, "%s=%d ",
		kPolicyRequiresSymbol,
		policy->requiresSymbol);
    len += snprintfcat(string, string_max, "%s=%d ",
		kPolicyNewPasswordRequired,
		policy->newPasswordRequired);
    len += snprintfcat(string, string_max, "%s=%d ",
		kPolicyNotGuessablePattern,
		policy->notGuessablePattern);
    len += snprintfcat(string, string_max, "%s=%llu ",
		kPolicyExpirationDateGMT,
		policy->expirationDateGMT);
    len += snprintfcat(string, string_max, "%s=%llu ",
		kPolicyHardExpireDateGMT,
		policy->hardExpireDateGMT);
    len += snprintfcat(string, string_max, "%s=%llu ",
		kPolicyMaxMinutesUntilChangePassword,
		policy->maxMinutesUntilChangePassword);
    len += snprintfcat(string, string_max, "%s=%llu ",
		kPolicyMaxMinutesUntilDisabled,
		policy->maxMinutesUntilDisabled);
    len += snprintfcat(string, string_max, "%s=%llu ",
		kPolicyMaxMinutesOfNonUse,
		policy->maxMinutesOfNonUse);
    len += snprintfcat(string, string_max, "%s=%llu ",
		kPolicyMaxFailedLoginAttempts,
		policy->maxFailedLoginAttempts);
    len += snprintfcat(string, string_max, "%s=%llu ",
		kPolicyMinChars,
		policy->minChars);
    len += snprintfcat(string, string_max, "%s=%llu ",
		kPolicyMaxChars,
		policy->maxChars);
    len += snprintfcat(string, string_max, "%s=%llu ",
		kPolicyMinutesUntilFailedLoginReset,
		policy->minutesUntilFailedLoginReset);

    //
    // If this is a user policy, include the user policy attributes.
    //
    if (isUser) {
        len += snprintfcat(string, string_max, "%s=%d ",
		kPolicyIsDisabled,
		policy->isDisabled);
        len += snprintfcat(string, string_max, "%s=%d ",
		kPolicyIsSessionKeyAgent,
		policy->isSessionKeyAgent);
        len += snprintfcat(string, string_max, "%s=%d ",
		kPolicyIsComputerAccount,
		policy->isComputerAccount);
        len += snprintfcat(string, string_max, "%s=%d ",
		kPolicyAdminClass,
		policy->adminClass);
        len += snprintfcat(string, string_max, "%s=%d ",
		kPolicyAdminNoChangePasswords,
		policy->adminNoChangePasswords);
        len += snprintfcat(string, string_max, "%s=%d ",
		kPolicyAdminNoSetPolicies,
		policy->adminNoSetPolicies);
        len += snprintfcat(string, string_max, "%s=%d ",
		kPolicyAdminNoCreate,
		policy->adminNoCreate);
        len += snprintfcat(string, string_max, "%s=%d ",
		kPolicyAdminNoDelete,
		policy->adminNoDelete);
        len += snprintfcat(string, string_max, "%s=%d ",
		kPolicyAdminNoClearState,
		policy->adminNoClearState);
        len += snprintfcat(string, string_max, "%s=%d ",
		kPolicyAdminNoPromoteAdmins,
		policy->adminNoPromoteAdmins);
        len += snprintfcat(string, string_max, "%s=%llu ",
		kPolicyLogOffTime,
		policy->logOffTime);
        len += snprintfcat(string, string_max, "%s=%llu ",
		kPolicyKickOffTime,
		policy->kickOffTime);
        len += snprintfcat(string, string_max, "%s=%llu ",
		kPolicyLastLoginTime,
		policy->lastLoginTime);
        len += snprintfcat(string, string_max, "%s=%llu ",
		kPolicyPasswordLastSetTime,
		policy->passwordLastSetTime);
    }

    if (strlen(string) >= string_max)
        return -E2BIG;
    else if (strlen(string) > 0) {
        //
        // Remove the final trailing space.
        //
        string[strlen(string) - 1] = '\0';
    }

    return -1;
}


