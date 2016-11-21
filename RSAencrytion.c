/*Author: Adhip Vihan
  Code for RSA Message signing & verification
  Language: C
*/

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>

void upper_string(char* s) {
   int c = 0;
   while (c<strlen(s)) {
      if (s[c] >= 'a' && s[c] <= 'z') {
        s[c] -= 32;
     }
     c++;
   }
}

void genPair(){

    int pid;
    int i;
    for(i=0;i<2;i++){

        pid = fork();

        if(pid<=0){
            if(i==0){
                char *genKey[]  = {"openssl","rsa","-in","rsaprivatekey1024.pem","-out","rsapublickey1024.pem","-outform","PEM","-pubout",NULL};
                execv("/usr/bin/openssl", genKey); 
            }
            else if(i==1){
                char *genKey2[]  = {"openssl","rsa","-in","rsaprivatekey2048.pem","-out","rsapublickey2048.pem","-outform","PEM","-pubout",NULL};
                execv("/usr/bin/openssl", genKey2); 
            }
        }else{
           waitpid(pid,NULL, 0);
        }

    }
}

int generateKey(){
    int pid;
    int i;


    for(i=0;i<2;i++){

        pid = fork();

        if(pid<=0){

            if(i==0){
                char *genKey1[]  = {"openssl","genrsa","-out","rsaprivatekey1024.pem","1024",NULL};  
                execv("/usr/bin/openssl", genKey1);
            }
            else if(i==1){
                char *genKey2[]  = {"openssl","genrsa","-out","rsaprivatekey2048.pem","2048",NULL}; 
                execv("/usr/bin/openssl", genKey2);
            }
        }else{
           waitpid(pid,NULL, 0);
        }

    }

       return 0; 

}

void encryption_helper(char* digest,char* prvKey,char * keyLen){
    int i;
    int pid;
    char hashFunction[10];
    char plainText[10];
    char cipher[40];
    struct timeval t0;
    struct timeval t1;
    float elapsed;

    memset(hashFunction,0,10);
	sprintf(hashFunction, "-%s", digest);
    
    upper_string(digest);
    char folder[20];
    memset(folder,0,20);
    sprintf(folder, "%s%s", keyLen,digest);
    gettimeofday(&t0, 0);

    for(i=1;i<=10;i++){
        memset(plainText,0,10);
	    sprintf(plainText, "msg/msg.%d", i);

        memset(cipher,0,40);
	    sprintf(cipher, "Output/%s/cipher.%d",folder,i);

        pid = fork();

        if(pid<=0){
            char *com[]  = {"openssl","dgst",hashFunction,"-sign",prvKey,"-out",cipher,plainText,NULL};
            execv("/usr/bin/openssl", com);
        }else{
           waitpid(pid,NULL, 0);
        }
    }

       gettimeofday(&t1, 0);
       elapsed = (t1.tv_sec - t0.tv_sec) * 1000.0f + (t1.tv_usec - t0.tv_usec) / 1000.0f;
       printf("%s %s Encryption done in %f milliseconds.\n",hashFunction,prvKey, elapsed);  
}

   void verification_helper(char *digest,char *pubKey,char * keyLen){
        int i=1;
        int pid;
        char hashFunction[10];
        char plainText[10];
        char cipher[40];
        struct timeval t0;
        struct timeval t1;
        float elapsed;

        memset(hashFunction,0,10);
	    sprintf(hashFunction, "-%s", digest);

        upper_string(digest);
        char folder[20];
        memset(folder,0,20);
        sprintf(folder, "%s%s", keyLen,digest);

    gettimeofday(&t0, 0);
    for(i;i<=10;i++){
        memset(plainText,0,10);
	    sprintf(plainText, "msg/msg.%d", 1);

        memset(cipher,0,40);
	    sprintf(cipher, "Output/%s/cipher.%d",folder,1);

        pid = fork();

        if(pid<=0){
            char *com[]  = {"openssl","dgst",hashFunction,"-verify",pubKey,"-signature",cipher,plainText,NULL};
            execv("/usr/bin/openssl", com);
        }else{
            waitpid(pid,NULL, 0);
        }
   }

       gettimeofday(&t1, 0);
       elapsed = (t1.tv_sec - t0.tv_sec) * 1000.0f + (t1.tv_usec - t0.tv_usec) / 1000.0f;
       printf("%s %s Verification done in %f milliseconds.\n", hashFunction,pubKey, elapsed);
}


int main(){

generateKey();
genPair();
    char hashFun1[10] = "sha1";
    char hashFun256[10] = "sha256";

int i=0;

/*For Encryption*/
for(i;i<5;i++){
    encryption_helper(hashFun1,"rsaprivatekey1024.pem","1024");
    encryption_helper(hashFun256,"rsaprivatekey1024.pem","1024");
    encryption_helper(hashFun1,"rsaprivatekey2048.pem","2048");
    encryption_helper(hashFun256,"rsaprivatekey2048.pem","2048");
}


/*For Verification*/
i=0;

for(i;i<5;i++){
    verification_helper(hashFun1,"rsapublickey1024.pem","1024");
	verification_helper(hashFun256,"rsapublickey1024.pem","1024");
	verification_helper(hashFun1,"rsapublickey2048.pem","2048");
	verification_helper(hashFun256,"rsapublickey2048.pem","2048");
}
    return 0;
}
