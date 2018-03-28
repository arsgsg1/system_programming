///////////////////////////////////////////////////////////////////
//  File name : proxy_cache.c                                    //
//  Date  : 2018/03/25                                           //
//  Os    : Ubuntu 16.04 LTS 64bits                              //
//  Author  : Yun Joa Houng                                      //
//  Student ID  : 2015722052                                     //
//  ---------------------------------                            //
//  Title : System Programming Assignment #1-1 (proxy server)    //
//  Descryption : user input url, programe is hashing input url  //
//                and create directory, file from hashed url     //
///////////////////////////////////////////////////////////////////
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <pwd.h>

#define DIR_LEN 256      //buffer size
#define HASH_DIR_LEN 3   //directory size
#define DEF_HIT 1
#define DEF_MISS  0
#define DEF_TER -1
typedef struct _CACHE_ATTR{
  int hit;
  int miss;
  int flag;
  time_t start;
  struct tm *gtp;
}CACHE_ATTR;

char root_dir[DIR_LEN]; //present working directory
///////////////////////////////////////////////////////
//  sha1_hash                                        //
//  ==============================================   //
//  Input: char *input_url -> hashing source url     //
//               hashed_url -> hashed destination url//
//  Output: char* ->  hashed url                     //
//          NULL  ->  error                          //
//  Purpos: string hash function                     //
///////////////////////////////////////////////////////
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
    return 0;
  }

  //write 16bit hex value from SHA1 method descryption
  for(i=0; i<sizeof(hashed_160bits); i++)
    sprintf(hashed_hex + i*2, "%02x", hashed_160bits[i]);

  strcpy(hashed_url, hashed_hex);

  return hashed_url;
}
/////////////////////////////////////////////////////////
// getHomeDir                                          //
// =================================================   //
// Input: char* -> home directory name for search      //
// Output: char * -> home directory                    //
// Purpose: getting home directory                     //
/////////////////////////////////////////////////////////
char *getHomeDir(char *home){
  struct passwd *usr_info = getpwuid(getuid());
  strcpy(home, usr_info->pw_dir);

  return home;
}

//////////////////////////////////////////////////////
//  makeDir                                         //
//  ==============================================  //
//  Input: char* src_url  ->  hashed url            //
//  Output: int ->  -1  fail                        //
//              ->  1   success                     //
//////////////////////////////////////////////////////
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
    umask(0000);
    if(0 > mkdir(create_dir, S_IRWXU | S_IRWXG | S_IRWXO)){
      fputs("in makeDir(), mkdir() error!", stderr);
    }
  }

  return 1;
}

//////////////////////////////////////////////////////////
//  createFile                                          //
//  ==================================================  //
//  Input:  char* src_url ->  hashed url                //
//  Output: int ->  -1 fail                             //
//  Purpose:  making file from hashed url               //
//////////////////////////////////////////////////////////
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

////////////////////////////////////////////////////
//  isHit                                         //
//  ===========================================   //
//  Input:  char* src_url ->  hashed url          //
//  Output: int ->  -1  fail                      //
//                  1   exist                     //
//                  0   no exist                  //
//  Purpose:  read directory, search file to exist//
////////////////////////////////////////////////////
int isHit(char *src_url)
{
  char path[DIR_LEN];
  char buf_dir[DIR_LEN];
  struct dirent *pFileTop=NULL, *pFileDown=NULL;
  DIR *pDirTop=NULL, *pDirDown=NULL;
  if(!src_url){fputs("in isHit() parameter is null!\n", stderr); return -1;}
  memcpy(path, root_dir, sizeof(root_dir));
  memcpy(buf_dir, src_url, HASH_DIR_LEN);

  if(NULL == (pDirTop = opendir(path))){
    fputs("in isHit(), opendir() error!\n", stderr);
    return -1;
  }

  for(pFileTop=readdir(pDirTop); pFileTop; pFileTop=readdir(pDirTop)){
    if(0 == strcmp(buf_dir, pFileTop->d_name)){
      if(NULL == (pDirDown = opendir(pFileTop->d_name))){fputs("in isHit(), opendir() error!\n", stderr); break;}
      for(pFileDown=readdir(pDirDown); pFileDown; pFileDown=readdir(pDirDown)){
        if(0 == strcmp(src_url+3, pFileDown->d_name)){

          if(pDirDown){closedir(pDirDown); pDirDown=NULL;}
          if(pDirTop){closedir(pDirTop); pDirTop=NULL;}

          return 1;
        }
      }
      closedir(pDirDown);
    }
  }
  if(pDirDown){closedir(pDirDown); pDirDown=NULL;}
  if(pDirTop){closedir(pDirTop); pDirTop=NULL;}
  return 0;
}
//////////////////////////////////////////////////////////////////
//  changeDir                                                   //
//  ================================                            //
//  Input: char* src_url  ->  hashed_url                        //
//  Output: int ->  -1  fail                                    //
//              ->  1   success                                 //
//  Purpose:  Change present working directory for create file  //
//            (from hashed url)                                 //
//////////////////////////////////////////////////////////////////
int changeDir(char *src_url)
{
  char path[DIR_LEN];
  char buf[DIR_LEN];
  char work[DIR_LEN];
  if(!src_url){fputs("in changeDir() parameter error\n", stderr); return -1;}
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
/*
writeLog
input_url, hashed_url, log에 기록할 정보 구조체, 로그파일을 open한 file descrypter
return -> int value -> 0 success
*/
int writeLog(char *input_url, char *src_url, CACHE_ATTR *cache_attr, int fd)
{
  char path[DIR_LEN], log[DIR_LEN*4];
  char hash_dir[HASH_DIR_LEN+1], hash_file[DIR_LEN];
  time_t now;
  struct tm *logTime;

  memset(path, 0, sizeof(path));
  memset(log, 0, sizeof(log));
  memset(hash_dir, 0, sizeof(hash_dir));
  memset(hash_file, 0, sizeof(hash_file));

  //initialized logging time
  time(&now);
  logTime = localtime(&now);
  //if 1=Hit, 0=Miss, -1=Terminated
  if(DEF_HIT == cache_attr->flag){  //if Hit
    memcpy(hash_dir, src_url, HASH_DIR_LEN);
    memcpy(hash_file, src_url+3, DIR_LEN-3);

    sprintf(log, "[%s]%s/%s-[%02d/%02d/%02d, %02d:%02d:%02d]\n", "Hit", hash_dir, hash_file,
  (logTime->tm_year+1900), (logTime->tm_mon+1), logTime->tm_mday,logTime->tm_hour ,logTime->tm_min, logTime->tm_sec);
    write(fd, log, strlen(log));

    memset(log, 0, sizeof(log));
    sprintf(log, "[%s]%s\n", "Hit", input_url);
    write(fd, log, strlen(log));
  }else if(DEF_MISS == cache_attr->flag){  //if Miss
    sprintf(log, "[%s]%s-[%02d/%02d/%02d, %02d:%02d:%02d]\n", "Miss", input_url, (logTime->tm_year+1900), (logTime->tm_mon+1),
  logTime->tm_mday, logTime->tm_hour, logTime->tm_min, logTime->tm_sec);
    write(fd, log, strlen(log));
  }else if(DEF_TER == cache_attr->flag){ //if Terminated
    sprintf(log, "[%s] run time: %02d sec. #request hit : %02d, miss : %02d\n", "Terminated",
     now-cache_attr->start, cache_attr->hit, cache_attr->miss);
    write(fd, log, strlen(log));
  }

  return 0;
}
int main(int argc, char* argv[])
{
  int fd; //logfile file descrypter
  char *input_url = 0, *hashed_url = 0;
  char temp[DIR_LEN] = "/cache", path[DIR_LEN], logPath[DIR_LEN]="/logfile";  //concaternate for root dir name var
  CACHE_ATTR cache_attr;

  input_url = (char*)malloc(sizeof(char)*DIR_LEN);
  hashed_url = (char*)malloc(sizeof(char)*DIR_LEN);
  if(!(input_url) || !(hashed_url))
    fputs("in main(), malloc() error!", stderr);

  //root directory setting
  getHomeDir(root_dir);
  strcat(root_dir, temp);
  memcpy(path, root_dir, sizeof(root_dir));

  //root driectory logic
  umask(0000);
  mkdir(path, S_IRWXU | S_IRWXG | S_IRWXO);
  chdir(path);

  //logfile logic(make logfile directory, time info init)
  memset(&cache_attr, 0, sizeof(cache_attr));
  time(&cache_attr.start); //initialized program start time
  cache_attr.gtp = gmtime(&cache_attr.start);
  getHomeDir(temp);
  umask(0000);
  sprintf(temp, "%s/%s", temp, "logfile");
  mkdir(temp, S_IRWXU | S_IRWXG | S_IRWXO);

  //create logfile(~/logfile/logfile.txt)
  sprintf(temp, "%s/%s", temp, "/logfile.txt"); // path is ~/logfile/logfile.txt
  if(0 > (fd = open(temp, O_RDWR | O_CREAT | O_APPEND, 0777)))
    fputs("in main() open() error!", stderr);


  while(1){
    printf("input URL> ");
    scanf("%s", input_url);
    if(0 == strcmp(input_url, "bye")){
      cache_attr.flag = DEF_TER;
      writeLog(input_url, hashed_url, &cache_attr, fd);
      close(fd);
      break;
    }
    if(0 == sha1_hash(input_url, hashed_url))
      fputs("sha1_hash() failed\n", stderr);

    if(0 == isHit(hashed_url)){
      cache_attr.miss += 1;
      cache_attr.flag = DEF_MISS;
      makeDir(hashed_url);

      if(0 > changeDir(hashed_url)){fputs("changeDir() error\n", stderr); break;}  //cd ~/caache/ef0
      createFile(hashed_url);
      chdir(path);  //cd ~/cache/
    }else{
      cache_attr.hit += 1;
      cache_attr.flag = DEF_HIT;
    }
    writeLog(input_url, hashed_url, &cache_attr, fd);
  }
  if(input_url) free(input_url);
  if(hashed_url) free(hashed_url);

  return 0;
}
