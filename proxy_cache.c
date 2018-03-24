#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <pwd.h>

#define DIR_LEN 256
#define HASH_DIR_LEN 3

char root_dir[DIR_LEN];

char *sha1_hash(char *input_url, char *hashed_url)
{
  if((!input_url) || (!hashed_url)) //parameter check
    return 0;

  unsigned char hashed_160bits[20];
  char hashed_hex[41];
  int i;

  memset(hashed_160bits, 0, sizeof(hashed_160bits));
  memset(hashed_hex, 0, sizeof(hashed_hex));

  if(0 == SHA1(input_url, strlen(input_url), hashed_160bits)){
    fputs("SHA1() error!\n", stderr);
  }

  //write 16bit hex value from SHA1 method descryption
  for(i=0; i<sizeof(hashed_160bits); i++)
    sprintf(hashed_hex + i*2, "%02x", hashed_160bits[i]);

  strcpy(hashed_url, hashed_hex);

  return hashed_url;
}

char *getHomeDir(char *home){
  struct passwd *usr_info = getpwuid(getuid());
  strcpy(home, usr_info->pw_dir);

  return home;
}  //cd ~/caache/ef0
/*
파라미터로 들어온 url에 대하여 앞 3글자만 토크나이징하여 디렉토리를 만드는 함수이다.
비고 : 생성한 모든 디렉토리는 모든 권한을 갖도록 구현한다. 즉, 8진수로 777 할당
*/
int makeDir(char *src_url)
{
  if(!src_url) return -1;

  char create_dir[DIR_LEN];  //creating new directory name var
  char path[DIR_LEN];
  int i;

  memcpy(path, root_dir, sizeof(path));

  if(path){ //pwd is home directory /home/yuncreate_dir[3] = '\0';

    //create new directory name 3 character
    memcpy(create_dir, src_url, HASH_DIR_LEN);
    create_dir[HASH_DIR_LEN] = '\0';

    //permission setting for 777
    umask(000);
    if(0 > mkdir(create_dir, S_IRWXU | S_IRWXG | S_IRWXO)){
      fputs("in makeDir(), mkdir() error!", stderr);
    }
  }

  return 1;
}
/*
  createFile
  descryption : 해싱된 URL을 가지고 파일을 만드는 함수
  parameter : 해싱된 URL
  returnValue : -1 = error, 1 = file make
  비고 : 파일 생성시 다양한 함수 사용가능,
*/
int createFile(char *src_url)
{
  char buf[DIR_LEN];  //file name
  int fd;

  memcpy(buf, src_url+HASH_DIR_LEN, (sizeof(char)*DIR_LEN)-HASH_DIR_LEN);
  //write mode | when no exist file, create file | when file exist, stop func
  if(0 > (fd = open(buf, O_WRONLY | O_CREAT))){
    //when you know error to spacify cause, using 'errno'
    fputs("in createFile(), open() error", stderr);
    return -1;
  }

  //Write File logic, when you want write file, using 'write' func
  //write();

  close(fd);
  return 1;
}
/*
  functionName: readDir
  descryption : 인자로 넘겨준 해싱된 URL에 대하여 directory가 이미 생성되었는지
  확인하고 createFile이 두 번 이상 호출되 | O_EXCL는 것을 방지하기 위한 함수 (루트 디렉토리 안에서)
  parameter : hashed_url
  returnValue : 0 = 생성되어 있지 않음, 1 = 생성되어 있음, -1 = error
*/
int readDir(char *src_url)
{
  char path[DIR_LEN];
  char buf_dir[DIR_LEN];
  struct dirent *pFile;
  DIR *pDir;
  if(!src_url){fputs("in readDir() parameter is null!\n", stderr); return -1;}
  memcpy(path, root_dir, sizeof(root_dir));

  if(NULL == (pDir = opendir(path))){
    fputs("in readFile(), opendir() error!\n", stderr);
    return -1;
  }
  for(pFile=readdir(pDir); pFile; pFile=readdir(pDir)){
    memcpy(buf_dir, src_url, HASH_DIR_LEN);
    if(0 == strcmp(buf_dir, pFile->d_name)){
      return 1;
    }
  }

  closedir(pDir);
  return 0;
}

int changeDir(char *src_url)
{
  char path[DIR_LEN];
  char buf[DIR_LEN];
  char work[DIR_LEN];
  memset(path, 0, sizeof(path));
  memset(buf, 0, sizeof(buf));

  memcpy(path, root_dir, sizeof(root_dir));
  memcpy(buf, src_url, HASH_DIR_LEN);
  sprintf(work, "%s/%s", path, buf);

  //present working directory is ~/cache, position of file is ~/cache
  //so, working directory of process change '~/cache/ef0...'
  if(0 > chdir(work)){fputs("in changeDir() chdir() error\n", stderr); return -1;}
  return 1;
}

int main(int argc, char* argv[])
{
  char *input_url = 0, *hashed_url = 0;
  char temp[DIR_LEN] = "/cache", path[DIR_LEN];  //concaternate for root dir name var

  input_url = (char*)malloc(sizeof(char)*DIR_LEN);
  hashed_url = (char*)malloc(sizeof(char)*DIR_LEN);
  if(!(input_url) || !(hashed_url))
    fputs("in main(), malloc() error!", stderr);

  //root directory setting
  getHomeDir(root_dir);
  strcat(root_dir, temp);
  memcpy(path, root_dir, sizeof(root_dir));

  while(1){
    printf("input URL> ");
    scanf("%s", input_url);
    if(0 == strcmp(input_url, "bye")){
      break;
    }
    sha1_hash(input_url, hashed_url);
    if(hashed_url)
        printf("%s\n", hashed_url);

    if(0 == readDir(hashed_url)){
      makeDir(hashed_url);

      if(0 > changeDir(hashed_url)){fputs("changeDir() error\n", stderr); break;}  //cd ~/caache/ef0
      createFile(hashed_url);
      chdir(path);  //cd ~/cache/
    }
  }
  if(input_url) free(input_url);
  if(hashed_url) free(hashed_url);
  return 0;
}
