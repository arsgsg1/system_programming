///////////////////////////////////////////////////////////////////
//  File name : proxy_cache.c                                    //
//  Date  : 2018/05/01                                           //
//  Os    : Ubuntu 16.04 LTS 64bits                              //
//  Author  : Yun Joa Houng                                      //
//  Student ID  : 2015722052                                     //
//  ---------------------------------                            //
//  Title : System Programming Assignment #2-2 (proxy server)    //
//  Descryption : user input url, programe is hashing input url  //
//                and create directory, file from hashed url     //
///////////////////////////////////////////////////////////////////
#include <arpa/inet.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <netdb.h>
#include <openssl/sha.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <pwd.h>
extern int h_errno;

#define DIR_LEN        256 //driectory name length
#define HASH_DIR_LEN   3   //directory size
#define DEF_HIT        1   //meaning hit
#define DEF_MISS       0   //meaning miss
#define DEF_TER_CHILD -1   //meaning child process Terminated
#define DEF_TER_SERV  -2   //meaning parent process Terminated
#define MAX_PROC       500 //child process list length
#define BUF_SIZE       1024//server sending message buffer size
#define PORTNO         40000//server communication port with client
#define HTTP_PORTNO    80
#define BACKLOG        10  //listening queue size
typedef struct _CACHE_ATTR{
  int hit;
  int miss;
  int flag;
  time_t start;
  int numofchild;
}CACHE_ATTR;
/*
  int hit -> for hit counting variable
      miss-> for miss counting variable
      flag-> for logfile control flag (hit, miss, Terminated child, Terminated server)
      numofchild-> parent process have numofchild process counting variable
  time_t start -> for loging start time each process
*/

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
char *sha1_hash(char *input_url, char *hashed_url)  //header
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
char *getHomeDir(char *home){ //header
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
int makeDir(char *src_url)  //add parameter header
{
  if(!src_url) return -1;

  char create_dir[DIR_LEN];  //creating new directory name var
  char path[DIR_LEN];
  int i;
  DIR *pDir = NULL;

  memcpy(path, root_dir, sizeof(path));
  memcpy(create_dir, src_url, HASH_DIR_LEN);
  create_dir[HASH_DIR_LEN] = '\0';

  if(NULL == (pDir = opendir(create_dir))){
    //permission setting for 777
    umask(0000);
    if(0 > mkdir(create_dir, S_IRWXU | S_IRWXG | S_IRWXO)){fputs("in makeDir(), mkdir() error!", stderr);}
  }else{closedir(pDir); pDir = NULL;}
  return 1;
}

//////////////////////////////////////////////////////////
//  createFile                                          //
//  ==================================================  //
//  Input:  char* src_url ->  hashed url                //
//  Output: int ->  -1 fail                             //
//  Purpose:  making file from hashed url               //
//////////////////////////////////////////////////////////
int createFile(char *src_url, char *buf) //header
{
  char file_name[DIR_LEN];  //file name
  int fd;

  memcpy(file_name, src_url+HASH_DIR_LEN, (sizeof(char)*DIR_LEN)-HASH_DIR_LEN);
  //write mode | when no exist file, create file | when file exist, stop func
  if(0 > (fd = open(file_name, O_RDWR | O_CREAT | O_APPEND, 0777))){
    //when you know error to spacify cause, using 'errno'
    fputs("in createFile(), open() error", stderr);
    return -1;
  }

  //Write File logic, when you want write file, using 'write' func
  //write();
  write(fd, buf, strlen(buf));

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
int isHit(char *src_url)  //add parameter header
{
  char path[DIR_LEN] = {0, };
  char buf_dir[DIR_LEN] = {0,};
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

          return DEF_HIT;
        }
      }
    }
  }
  if(pDirDown){closedir(pDirDown); pDirDown=NULL;}
  if(pDirTop){closedir(pDirTop); pDirTop=NULL;}
  return DEF_MISS;
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
int changeDir(char *src_url)  //add parameter header
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

//////////////////////////////////////////////////////////////////////////
//  writeLogFile                                                        //
//  ====================================================================//
//  Input : char *input url -> input url                                //
//                src_url -> hashed_url                                 //
//          CACHE_ATTR *cache_attr -> data struct for program loging    //
//          FILE *log_fp -> log file's FILE struct pointer              //
//  output : int -> 0 success                                           //
//               -> -1  failed                                          //
//  Purpose : program status writng log file                            //
//  1. hit, miss count                                                  //
//  2. if hit, hashed_url and input_url                                 //
//  3. if miss, input url                                               //
//  4. if Terminated, runtime, hit count, miss count                    //
//  5. every log has local time loging                                  //
//////////////////////////////////////////////////////////////////////////
int writeLogFile(char *input_url, char *src_url, CACHE_ATTR *cache_attr, FILE *fp)
{ //header
  char hash_dir[HASH_DIR_LEN+1], hash_file[DIR_LEN];
  time_t now;
  struct tm *logTime;

  if(NULL == fp){
    fputs("in writeLogFile() File pointer error\n", stderr);
    return -1;
  }

  time(&now);
  logTime = localtime(&now);
  memset(hash_dir, 0, sizeof(hash_dir));
  memset(hash_file, 0, DIR_LEN);
  memcpy(hash_dir, src_url, HASH_DIR_LEN);
  memcpy(hash_file, src_url+3, DIR_LEN-3);
  //if 1 = hit, -1 = Terminated
  if(DEF_HIT == cache_attr->flag){
    fprintf(fp, "[%s] ServerPID : %d | %s/%s-[%02d/%02d/%02d, %02d:%02d:%02d]\n","Hit", getpid(), hash_dir, hash_file,
  logTime->tm_year+1900, logTime->tm_mon+1, logTime->tm_mday, logTime->tm_hour, logTime->tm_min, logTime->tm_sec);
    fprintf(fp, "[%s]%s\n", "Hit", input_url);
  }else if(DEF_MISS == cache_attr->flag){
    fprintf(fp, "[%s] ServerPID : %d | %s-[%02d/%02d/%02d, %02d:%02d:%02d]\n","Miss", getpid(), input_url, logTime->tm_year+1900, logTime->tm_mon+1, logTime->tm_mday, logTime->tm_hour, logTime->tm_min, logTime->tm_sec);
  }else if(DEF_TER_CHILD == cache_attr->flag){
    fprintf(fp, "[%s] ServerPID : %d | run time: %ldsec. #request hit : %d, miss : %d\n","Terminated", getpid(), now-cache_attr->start, cache_attr->hit, cache_attr->miss);
  }else if(DEF_TER_SERV == cache_attr->flag){
    fprintf(fp, "**SERVER** [%s] run time: %ld sec. #sub process: %d\n", "Terminated", now-cache_attr->start, cache_attr->numofchild);
  }
  fflush(fp);
  return 0;
}
///////////////////////////////////////////////////////////////////////////////////
//  child_handler                                                                //
//  =============================================================================//
//  Purpose : child signal handling                                              //
///////////////////////////////////////////////////////////////////////////////////
static void child_handler()
{
  pid_t child_pid;
  int status;
  while(0 < (child_pid = waitpid(-1, &status, WNOHANG))){

  }
}
void reqWebResClnt(int web_sock_fd, int clnt_fd, char *request_msg, char *hashed_url)
{
  char response_buf[BUF_SIZE] = {0, };
  int read_len;
  write(web_sock_fd, request_msg, BUF_SIZE);
  printf("Send Web : %s\n===============\n", request_msg);
  while(0 < (read_len = read(web_sock_fd, response_buf, BUF_SIZE))){
    printf("Receive Web: %s\n=============\n", response_buf);
    createFile(hashed_url, response_buf);
    write(clnt_fd, response_buf, read_len);
  }
}
void resClnt(int clnt_sock_fd, char *src_url)
{
  char dir_buf[DIR_LEN] = {0, };
  char file_buf[DIR_LEN] = {0, };
  char buf[BUF_SIZE] = {0, };
  DIR *pDirTop = NULL, *pDirDown = NULL;
  struct dirent *pFileTop = NULL, *pFileDown = NULL;
  int cache_fd, read_len;
  if(NULL == (pDirTop = opendir(root_dir))){
    puts("can't open directory in resClnt()\n");
    return;
  }
  //파일을 cache 디렉토리에서 검색하여 읽어들이고 클라이언트에게 전달한다.
  for(pFileTop = readdir(pDirTop); pFileTop; pFileTop = readdir(pDirTop)){
    if(0 == strncmp(src_url, pFileTop->d_name, HASH_DIR_LEN)){
      pDirDown = opendir(pFileTop->d_name);
      for(pFileDown = readdir(pDirDown); pFileDown; pFileDown = readdir(pDirDown)){
        if(0 == strcmp(src_url + 3, pFileDown->d_name)){
          cache_fd = open(pFileDown->d_name, O_RDONLY);
          while(0 < (read_len = read(cache_fd, buf, BUF_SIZE))){ //읽은 바이트 수 만큼 client에게 전달
            write(cache_fd, buf, read_len);
          }
          close(cache_fd);
          closedir(pDirDown);
          closedir(pDirTop);
          break;
        }
      }
    }
  }

}

char *requestParsedURL(char *request, char *urlBuf)
{
  char tmp[BUF_SIZE] = {0,};
  char method[20] = {0,};
  char *tok;
  strcpy(tmp, request);
  tok = strtok(tmp, " ");
  strcpy(method, tok);
  if(0 == strcmp(method, "GET")){
    tok = strtok(NULL, " ");  //http://www.~~~.~~~
    tok = strtok(tok, "/");
    tok = strtok(NULL, "/");
    strcpy(urlBuf, tok);
  }
  return urlBuf;
}
char *getIPAddr(char *addr)
{
  struct hostent* hent;
  char *haddr;
  int len = strlen(addr);
  if(NULL != (hent = (struct hostent*)gethostbyname(addr))){
    haddr = inet_ntoa(*((struct in_addr*)hent->h_addr_list[0]));
  }
  return haddr;
}

int main(int argc, char* argv[])
{
  int fd; //logfile file descrypter
  int opt = 1;
  char *input_url = 0, *hashed_url = 0;
  char temp[DIR_LEN] = "/cache", path[DIR_LEN], logPath[DIR_LEN]="/logfile";  //concaternate for root dir name var
  CACHE_ATTR cache_attr;
  FILE *log_fp = 0;
  pid_t parent_pid, child_pid;
  pid_t child_list[MAX_PROC];
  int statloc, user_count = 0, clnt_port = 0;
  DIR *pDir = NULL;

  //socket variable
  int clnt_fd, serv_fd, addr_len = 0, msg_len, len_read;
  struct sockaddr_in serv_addr, clnt_addr;
  char clnt_ip[BUF_SIZE], msg[BUF_SIZE];

  input_url = (char*)malloc(sizeof(char)*DIR_LEN);
  hashed_url = (char*)malloc(sizeof(char)*DIR_LEN);
  if(!(input_url) || !(hashed_url))
    fputs("in main(), malloc() error!", stderr);

  //root directory setting
  getHomeDir(root_dir);
  strcat(root_dir, temp);
  memcpy(path, root_dir, sizeof(root_dir));

  //make root driectory logic
  if(NULL == (pDir = opendir(path))){
    umask(0000);
    mkdir(path, S_IRWXU | S_IRWXG | S_IRWXO);
  }else{ closedir(pDir); pDir = NULL;}
  chdir(path);

  //logfile logic(make logfile directory, time info init)
  memset(&cache_attr, 0, sizeof(cache_attr));
  time(&cache_attr.start); //initialized program start time
  getHomeDir(temp);
  sprintf(temp, "%s/%s", temp, "logfile");
  if(NULL == (pDir = opendir(temp))){
    umask(0000);
    mkdir(temp, S_IRWXU | S_IRWXG | S_IRWXO);
  }else{ closedir(pDir); pDir = NULL; }

  //create logfile(~/logfile/logfile.txt)
  sprintf(temp, "%s/%s", temp, "/logfile.txt"); // path is ~/logfile/logfile.txt
  if(0 > (fd = open(temp, O_RDWR | O_CREAT | O_APPEND, 0777)))
    fputs("in main() open() error!", stderr);
  log_fp = fdopen(fd, "r+");

  //get process id logic
  parent_pid = getpid();

  //socket setting logic
  if(0 > (serv_fd = socket(PF_INET, SOCK_STREAM, 0))){
    fputs("in main() can't open stream socket", stderr);
    return -1;
  }
  setsockopt(serv_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
  //initialize socket information
  memset(&serv_addr, 0, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  serv_addr.sin_port = htons(PORTNO);

  if(0 > bind(serv_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr))){
    fputs("in main() can't bind socket.\n", stderr);
    return -1;
  }
  if(0 > listen(serv_fd, BACKLOG)){
    fputs("in main() can't listening socket.\n", stderr);
    return -1;
  }

  //initialize signal handler
  signal(SIGCHLD, (void *)child_handler);

  while(1){
    memset(&clnt_addr, 0, sizeof(clnt_addr));
    addr_len = sizeof(clnt_addr);
    clnt_fd = accept(serv_fd, (struct sockaddr*)&clnt_addr, &addr_len);
    if(0 > (child_pid = fork())){
      fputs("can't make process.\n", stderr);
      close(clnt_fd);
      close(serv_fd);
      fclose(log_fp);
      break;
    }else if(0 == child_pid){ //child logic
      time(&cache_attr.start);
      strncpy(clnt_ip, inet_ntoa(clnt_addr.sin_addr), sizeof(clnt_ip));
      printf("[%s : %d] client was connected\n", clnt_ip, ntohs(clnt_addr.sin_port));

      while(0 < read(clnt_fd, msg, BUF_SIZE)){

        //Parsed URL logic
        requestParsedURL(msg, input_url); //extract host url from request msg

        //hit miss logic
        if(0 == sha1_hash(input_url, hashed_url))
          fputs("sha1_hash() failed\n", stderr);

        if(DEF_MISS == isHit(hashed_url)){
          //if cache miss, proxy request to web server
          //so, Make socket, request http format message
          char *ip_addr = getIPAddr(input_url);
          int web_sock_fd;
          struct sockaddr_in web_serv_addr;
          if(0 > (web_sock_fd = socket(PF_INET, SOCK_STREAM, 0))){
            printf("can't create socket.\n");
            return -1;
          }

          memset(&web_serv_addr, 0, sizeof(web_serv_addr));
          web_serv_addr.sin_family = AF_INET;
          web_serv_addr.sin_addr.s_addr = inet_addr(ip_addr);
          web_serv_addr.sin_port = htons(HTTP_PORTNO);
          if(0 > connect(web_sock_fd, (struct sockaddr*)&web_serv_addr, sizeof(web_serv_addr))){
            printf("can't connect.\n");
            return -1;
          }
          //write request message http format

          //read data from web server

          cache_attr.miss += 1;
          cache_attr.flag = DEF_MISS;
          makeDir(hashed_url);

          if(0 > changeDir(hashed_url)){fputs("changeDir() error\n", stderr); break;}  //cd ~/caache/ef0
          reqWebResClnt(web_sock_fd, clnt_fd, msg, hashed_url);
          close(web_sock_fd);
        }else{
          cache_attr.hit += 1;
          cache_attr.flag = DEF_HIT;
          //hit response
          if(0 > changeDir(hashed_url)){fputs("changeDir() error\n", stderr); break;}  //cd ~/caache/ef0
          resClnt(clnt_fd, hashed_url);
        }
        chdir(path);  //cd ~/cache/
        writeLogFile(input_url, hashed_url, &cache_attr, log_fp);
        break;
      }
      printf("[%s : %d] client was disconnected\n", clnt_ip, ntohs(clnt_addr.sin_port));
      close(clnt_fd);
      close(serv_fd);
      fclose(log_fp);
      break;
    }else{  //parent logic
      //control child process list
      //write log
      //closing file descrypter
    }

  }
  if(input_url) free(input_url);
  if(hashed_url) free(hashed_url);

  return 0;
}
