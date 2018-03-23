#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <pwd.h>

char *sha1_hash(char *input_url, char *hashed_url)
{
  if((!input_url) || (!hashed_url))
    return 0;

  unsigned char hashed_160bits[20];
  char hashed_hex[41];
  int i;

  memset(hashed_160bits, 0, sizeof(hashed_160bits));
  memset(hashed_hex, 0, sizeof(hashed_hex));

  if(0 == SHA1(input_url, strlen(input_url), hashed_160bits)){
    fputs("SHA1() error!\n", stderr);
  }

  for(i=0; i<sizeof(hashed_160bits); i++)
    sprintf(hashed_hex + i*2, "%02x", hashed_160bits[i]);

  strcpy(hashed_url, hashed_hex);

  return hashed_url;
}

char *getHomeDir(char *home){
  struct passwd *usr_info = getpwuid(getuid());
  strcpy(home, usr_info->pw_dir);

  return home;
}
/*
파라미터로 들어온 url에 대하여 앞 3글자만 토크나이징하여 디렉토리를 만드는 함수이다.
비고 : 생성한 모든 디렉토리는 모든 권한을 갖도록 구현한다. 즉, 8진수로 777 할당
*/
int makeDir(char *src_url)
{
  if(!src_url) return -1;

  char root_dir[20] = "/cache";  //concaternate for root dir name var
  char create_dir[10];  //creating new directory name var
  char *working = 0; //write working dir var
  int i;

  working = (char*)malloc(sizeof(char) * 256);
  if(!working){fputs("in makeDir() malloc() error!\n", stderr); return -1;}

  if(getHomeDir(working)){ //pwd is home directory /home/yun
    //change directory into cache
    strcat(working, root_dir);

    //create new directory name 3 character
    strncpy(create_dir, src_url, 3);
    create_dir[3] = '\0';

    umask(0000);  //permission setting for 777
    if(0 > mkdir(create_dir, S_IRWXU | S_IRWXG | S_IRWXO)){
      fputs("in makeDir(), mkdir() error!", stderr);
    }
  }

  if(working) free(working);
  return 1;
}



int main(int argc, char* argv[])
{
  char *input_url = 0, *hashed_url = 0;

  input_url = (char*)malloc(sizeof(char)*255);
  hashed_url = (char*)malloc(sizeof(char)*255);
  if(!(input_url) || !(hashed_url))
    fputs("in main(), malloc() error!", stderr);


  while(1){
    printf("input URL> ");
    scanf("%s", input_url);
    if(0 == strcmp(input_url, "bye")){
      break;
    }
    sha1_hash(input_url, hashed_url);
    if(hashed_url)
        printf("%s\n", hashed_url);

    if(0 > makeDir(hashed_url)){
      fputs("makeDir() parameter error!", stderr);
    }
  }
  if(input_url) free(input_url);
  if(hashed_url) free(hashed_url);
  return 0;
}
