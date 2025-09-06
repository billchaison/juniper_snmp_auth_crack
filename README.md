# juniper_snmp_auth_crack
Juniper SNMP v3 authentication-key password recovery tool.

This utility can be used to attempt offline cracking of SNMP v3 authentication keys stored in Juniper configs.

**Source code compile with gcc**

```c
/*
Juniper SNMP v3 authentication-key password recovery tool.  Bill Chaison, free to use under BSD-3-Clause.

compile: gcc juniper_snmpv3_auth_crack.c -o juniper_snmpv3_auth_crack -lcrypto

usage: juniper_snmpv3_auth_crack <mode> <engine ID hex> <auth-key hex> <wordlist>

<mode>          = authentication-md5
                  authentication-sha
                  authentication-sha224
                  authentication-sha256
                  authentication-sha384
                  authentication-sha512
<engine ID hex> = Hex string obtained from "show snmp v3" the value of "Local engine ID:" without spaces.
                  Or acquired from nmap script snmp-info and wireshark capture of the agent response msgAuthoritativeEngineID field.
<auth-key hex>  = The hex string from the decoded $9$ reversible string in the config.
                  (e.g.) "request system decrypt password $9$..." or https://github.com/mhite/junosdecode
<wordlist>      = The path to your wordlist file, one password per line.

(example test cases for "password")
juniper_snmpv3_auth_crack authentication-md5 80000a4c0430 10c6790a7e4a9a0e1d49305674456004 /home/user/snmp_passwords.txt
juniper_snmpv3_auth_crack authentication-sha 80000a4c0430 262aeb10bd4fcad298132dd0a46a818b85ccaafc /home/user/snmp_passwords.txt
juniper_snmpv3_auth_crack authentication-sha224 80000a4c0430 d0d10777524609a045ba41b469e1e1105954c61d6df169a1d7ec9d94 /home/user/snmp_passwords.txt
juniper_snmpv3_auth_crack authentication-sha256 80000a4c0430 adeb6305985700d36a2856667fe02ab1626a1e3ac757c9ae642c57111264184a /home/user/snmp_passwords.txt
juniper_snmpv3_auth_crack authentication-sha384 80000a4c0430 eeefbb61481ffe02a24049605ebed1ed7af8340755bdea9705c2b7249d05de6c2f8619fbf6ed79bbc2a8ba65e8ef35de /home/user/snmp_passwords.txt
juniper_snmpv3_auth_crack authentication-sha512 80000a4c0430 f4cf123d7d0330ed5049e58f70d2d885b1ffd98965e51524b86214b8343d68b6c6d57742d1344583e40831365de02522052e0a2ca099af3a297dc772731ca76d /home/user/snmp_passwords.txt

Juniper converts authentication-password to authentication-key using RFC-3414 when stored in the config.
Engine ID must be from 1 to 32 bytes long.
Passwords must be from 8 to 1024 bytes long.
*/

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <openssl/evp.h>

#define MAXPWLEN 1024
#define MINPWLEN 8
#define MAXEIDLEN 32
#define MINEIDLEN 1
#define MAXKEYLEN 64

int inkeybuflen = 0;
int eidbuflen;
u_char eidbuf[MAXEIDLEN * 2], inkeybuf[MAXKEYLEN * 2], outkeybuf[MAXKEYLEN * 2];
const EVP_MD *halg;

// adapted from RFC-3414
void password_to_key(u_char *password, u_int passwordlen, u_char *engineID, u_int engineLength, u_char *key)
{
   EVP_MD_CTX *ctx = EVP_MD_CTX_new();
   u_char *cp, password_buf[MAXPWLEN];
   u_long password_index = 0;
   u_long count = 0, i;

   EVP_DigestInit(ctx, halg);
   while(count < 1048576)
   {
      cp = password_buf;
      for(i = 0; i < 64; i++)
      {
         *cp++ = password[password_index++ % passwordlen];
      }
      EVP_DigestUpdate(ctx, (const unsigned char *)password_buf, 64);
      count += 64;
   }
   EVP_DigestFinal(ctx, key, NULL);
   memcpy(password_buf, key, inkeybuflen);
   memcpy(password_buf + inkeybuflen, engineID, engineLength);
   memcpy(password_buf + inkeybuflen + engineLength, key, inkeybuflen);
   EVP_DigestInit(ctx, halg);
   EVP_DigestUpdate(ctx, (const unsigned char *)password_buf, (inkeybuflen * 2) + engineLength);
   EVP_DigestFinal(ctx, key, NULL);
   EVP_MD_CTX_free(ctx);
}

void usage(char *arg)
{
   printf("usage: %s <mode> <engine ID hex> <auth-key hex> <wordlist>\n\n", arg);
   printf("<mode> = authentication-md5\n");
   printf("         authentication-sha\n");
   printf("         authentication-sha224\n");
   printf("         authentication-sha256\n");
   printf("         authentication-sha384\n");
   printf("         authentication-sha512\n");
   printf("<engine ID hex> = Hex string obtained from \"show snmp v3\" the value of\n");
   printf("                  \"Local engine ID:\" without spaces. Or acquired from nmap\n");
   printf("                  script snmp-info and wireshark capture of the agent response\n");
   printf("                  msgAuthoritativeEngineID field.\n");
   printf("<auth-key hex> = The hex string from the decoded $9$ reversible string in the\n");
   printf("                 config.\n");
   printf("<wordlist> = The path to your wordlist file, one password per line.\n");
}

int parsehex(char *arg, int *buflen, u_char *buf, int min, int max)
{
   int arglen = strlen(arg);
   int i, j;

   if(arglen < (min * 2) || arglen > (max * 2)) return -1;
   if(arglen % 2) return -1;
   for(i = 0, j = 0; i < arglen; i += 2, j++)
   {
      if(arg[i] >= '0' && arg[i] <= '9')
      {
         *(buf + j) = (u_char)((arg[i] - '0') * 16);
      }
      else if(arg[i] >= 'a' && arg[i] <= 'f')
      {
         *(buf + j) = (u_char)((arg[i] - 'W') * 16);
      }
      else
      {
         return -1;
      }
      if(arg[i + 1] >= '0' && arg[i + 1] <= '9')
      {
         *(buf + j) += (u_char)(arg[i + 1] - '0');
      }
      else if(arg[i + 1] >= 'a' && arg[i + 1] <= 'f')
      {
         *(buf + j) += (u_char)(arg[i + 1] - 'W');
      }
      else
      {
         return -1;
      }
   }
   *buflen = arglen / 2;

   return 0;
}

int parseargs(char *argv[])
{
   int inhashlen = 0;

   if(!strcmp(argv[1], "authentication-md5")) { inkeybuflen = 16; halg = EVP_md5(); }
   if(!strcmp(argv[1], "authentication-sha")) { inkeybuflen = 20; halg = EVP_sha1(); }
   if(!strcmp(argv[1], "authentication-sha224")) { inkeybuflen = 28; halg = EVP_sha224(); }
   if(!strcmp(argv[1], "authentication-sha256")) { inkeybuflen = 32; halg = EVP_sha256(); }
   if(!strcmp(argv[1], "authentication-sha384")) { inkeybuflen = 48; halg = EVP_sha384(); }
   if(!strcmp(argv[1], "authentication-sha512")) { inkeybuflen = 64; halg = EVP_sha512(); }
   if(inkeybuflen == 0)
   {
      fprintf(stderr, "Error: invalid <mode> specified.\n");
      return -1;
   }
   if(parsehex(argv[2], &eidbuflen, &eidbuf[0], MINEIDLEN, MAXEIDLEN))
   {
      fprintf(stderr, "Error: invalid string specified for <engine ID hex>.\n");
      return -1;
   }
   if(parsehex(argv[3], &inhashlen, &inkeybuf[0], inkeybuflen, inkeybuflen))
   {
      fprintf(stderr, "Error: invalid string specified for <auth-key hex>.\n");
      return -1;
   }
   if(inhashlen != inkeybuflen)
   {
      fprintf(stderr, "Error: invalid string specified for <auth-key hex>.\n");
      return -1;
   }

   return 0;
}

int main(int argc, char *argv[])
{
   u_char pw[1500];
   u_int pwlen, h, i;
   FILE *fp;

   if(argc != 5)
   {
      usage(argv[0]);
      return -1;
   }
   if(parseargs(argv))
   {
      return -1;
   }
   fp = fopen(argv[4], "r");
   if(fp == NULL)
   {
      fprintf(stderr, "Error: could not open <wordlist>.\n");
      return -1;
   }
   while(fgets(pw, 1400, fp) != NULL)
   {
      pw[strcspn(pw, "\r\n")] = 0;
      pwlen = strlen(pw);
      if(pwlen >= MINPWLEN && pwlen <= MAXPWLEN)
      {
         fprintf(stderr, "."); fflush(stderr); // hash mark test password.
         password_to_key(pw, pwlen, eidbuf, eidbuflen, outkeybuf);
         h = 0;
         for(i = 0; i < inkeybuflen; i++)
         {
            if(outkeybuf[i] == inkeybuf[i]) h++;
         }
         if(h == inkeybuflen)
         {
            printf("\nSUCCESS: %s\n", pw);
            return 0;
         }
      }
      else
      {
         fprintf(stderr, "x"); fflush(stderr); // hash mark skip password.
      }
   }
   fclose(fp);
   printf("\nFAILED: password not recovered.\n");

   return 1;
}
```

**Example getting the parts needed**

The authentication-key from the config.

![alt text](https://raw.githubusercontent.com/billchaison/juniper_snmp_auth_crack/main/jc00.png)

The Engine ID from the cli or NMAP snmp-info script.

![alt text](https://raw.githubusercontent.com/billchaison/juniper_snmp_auth_crack/main/jc01.png)

The decoded authentication-key as hex from the cli or other open source tool.

![alt text](https://raw.githubusercontent.com/billchaison/juniper_snmp_auth_crack/main/jc02.png)

**Example successful and unsuccessful password recovery**

![alt text](https://raw.githubusercontent.com/billchaison/juniper_snmp_auth_crack/main/jc03.png)
