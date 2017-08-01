/*  This program was contributed by Shane Watts
    [modifications by AGM and kukuk]

    You need to add the following (or equivalent) to the
    /etc/pam.d/check_user file:
# check authorization
auth       required     pam_unix.so
account    required     pam_unix.so
*/

#include <unistd.h>
#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>  
#include <string.h> 

struct pam_response *reply;

//function used to get user input  
int function_conversation(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr)  
{  
    *resp = reply;  
    return PAM_SUCCESS;  
} 

int main(int argc, char *argv[])
{
    pam_handle_t *pamh=NULL;
    int retval;
    char *user=NULL;
    char *pass;
    const struct pam_conv local_conversation = { function_conversation, NULL };  
    pam_handle_t *local_auth_handle = NULL; // this gets set by pam_start
    
    pass = malloc(128);

    printf ("Username: ");
    scanf ("%ms", &user);
    pass = getpass("Password: ");

    retval = pam_start("sshd", user, &local_conversation, &local_auth_handle);  

    if (retval != PAM_SUCCESS)  
    {  
        printf("pam_start returned: %d\n ", retval);  
        return 0;  
    }  

    reply = (struct pam_response *)malloc(sizeof(struct pam_response));  

    reply[0].resp = strdup(pass);  
    reply[0].resp_retcode = 0;  
    retval = pam_authenticate(local_auth_handle, 0);


    if (retval != PAM_SUCCESS)  
    {  
        if (retval == PAM_AUTH_ERR)  
        {  
            printf("Authentication failure.\n");  
        }  
        else  
        {  
            printf("pam_authenticate returned %d\n", retval);  
        }  
        return 0;  
    }  

    printf("Authenticated.\n");  
    retval = pam_end(local_auth_handle, retval);  

    if (retval != PAM_SUCCESS)  
    {  
        printf("pam_end returned\n");  
        return 0;  
    }  }