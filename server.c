///////////////////////////////////////////////////////////////////
//  File name : proxy_cache.c                                    //
//  Date  : 2018/05/17                                           //
//  Os    : Ubuntu 16.04 LTS 64bits                              //
//  Author  : Yun Joa Houng                                      //
//  Student ID  : 2015722052                                     //
//  ---------------------------------                            //
//  Title : System Programming Assignment #2-3 (proxy server)    //
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

#define _DEBUG_
#define DIR_LEN        1024 //driectory name length
#define HASH_DIR_LEN   3   //directory size
#define DEF_HIT        1   //meaning hit
#define DEF_MISS       0   //meaning miss
#define DEF_TER_CHILD -1   //meaning child process Terminated
#define DEF_TER_SERV  -2   //meaning parent process Terminated
#define BUF_SIZE       1024//server sending message buffer size
#define PORTNO         38029//server communication port with client
#define HTTP_PORTNO    80
#define BACKLOG        10  //listening queue size
#define STAT_SERV      1
#define STAT_CHILD     0
#define STAT_LOG       1
#define STAT_NOT_LOG   0
typedef struct _CACHE_ATTR{
  int hit;
  int miss;
  int flag;
  time_t start;
  int numofchild;
  char input_url[BUF_SIZE];
  char hashed_url[BUF_SIZE];
}CACHE_ATTR;
typedef struct _ST_HANDLER{
  int clnt_fd;
  char state;
  FILE* log_fp;
}ST_HANDLER;

ST_HANDLER gst_handler;
CACHE_ATTR gcache_attr;
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
    if(NULL == input_url || NULL == src_url || 0 == strlen(input_url) || 0 == strlen(src_url))
      return -1;
    fprintf(fp, "[%s] %s/%s-[%02d/%02d/%02d, %02d:%02d:%02d]\n","Hit", hash_dir, hash_file,
  logTime->tm_year+1900, logTime->tm_mon+1, logTime->tm_mday, logTime->tm_hour, logTime->tm_min, logTime->tm_sec);
    fprintf(fp, "[%s]%s\n", "Hit", input_url);
  }else if(DEF_MISS == cache_attr->flag){
    if(NULL == input_url || NULL == src_url || 0 == strlen(input_url) || 0 == strlen(src_url))
      return -1;
    fprintf(fp, "[%s] %s-[%02d/%02d/%02d, %02d:%02d:%02d]\n","Miss", input_url, logTime->tm_year+1900, logTime->tm_mon+1, logTime->tm_mday, logTime->tm_hour, logTime->tm_min, logTime->tm_sec);
  }else if(DEF_TER_SERV == cache_attr->flag){
    fprintf(fp, "**SERVER** [%s] run time: %ld sec. #sub process: %d\n", "Terminated", now-cache_attr->start, cache_attr->numofchild);
  }
  fflush(fp);
  return 0;
}
///////////////////////////////////////////////////////////////////////////////////
//  child_handler                                                                //
//  =============================================================================//
//  Purpose : child signal handling, wait child process                          //
///////////////////////////////////////////////////////////////////////////////////
static void sigchld_handler()
{
  pid_t child_pid;
  int status;
  while(0 < (child_pid = waitpid(-1, &status, 0))){

  }
}
///////////////////////////////////////////////////////////////////////////////////
// sigint_handler                                                                //
// =======================                                                       //
// Purpose : sigint signal handling, write log server state                      //
///////////////////////////////////////////////////////////////////////////////////
static void sigint_handler()
{
  if(STAT_SERV == gst_handler.state){
    gcache_attr.flag = DEF_TER_SERV;
    writeLogFile(gcache_attr.input_url, gcache_attr.hashed_url, &gcache_attr, gst_handler.log_fp);
  }
  exit(1);
}
/////////////////////////////////////////////////////////////////////////////////////////
//  sigalarm_handler                                                                   //
//  =======================                                                            //
//  Purpose : if alarm signal enable, program response to client that '응답없음' message //
/////////////////////////////////////////////////////////////////////////////////////////

static void sigalarm_handler()
{
  char response_message[BUF_SIZE];
  char response_header[BUF_SIZE];
  sprintf(response_message,
          "<h1>응답없음</h1><br>");
  sprintf(response_header,
          "HTTP/1.0 200 OK\r\n"
          "Server:2018 simple web server\r\n"
          "Content-length:%lu\r\n"
          "Content-type:text/html\r\n\r\n", strlen(response_message));
  write(gst_handler.clnt_fd, response_header, strlen(response_header));
  write(gst_handler.clnt_fd, response_message, strlen(response_message));
  gcache_attr.flag = DEF_MISS;
  writeLogFile(gcache_attr.input_url, gcache_attr.hashed_url, &gcache_attr, gst_handler.log_fp);
  exit(1);
}
//////////////////////////////////////////////////////////////////////////////////////////
//  reqFilter                                                                           //
//  ==========================                                                          //
//  char *request_msg -> parsing text : 'text/html' from client for filtering log       //
//  ==========================                                                          //
//  Purpose : filtering log                                                             //
//////////////////////////////////////////////////////////////////////////////////////////
char reqFilter(char *request_msg)
{
  char tmp[BUF_SIZE] = {0, };
  char *tok;
  strcpy(tmp, request_msg);

  tok = strtok(tmp, "\r\n ");
  while(1){
    tok = strtok(NULL, "\r\n ,");
    if(0 == strcmp(tok, "Accept:")){
      tok = strtok(NULL, "\r\n ,");
      if(0 == strcmp(tok, "text/html"))
        return STAT_LOG;
      else
        return STAT_NOT_LOG;
    }
  }

  if(0 == strcmp(tok, "text/html")){
    return STAT_LOG;
  }else{
    return STAT_NOT_LOG;
  }
}
///////////////////////////////////////////////////////////////////////////////////////
//  reqWebResClnt                                                                    //
//  ==================================                                               //
//  int web_sock_fd -> web server socket file descrypter                             //
//  int clnt_fd -> client socket file descrypter                                     //
//  char *request_msg -> request message from client                                 //
//  char *hashed_url -> input url hashed string                                      //
//  ==================================                                               //
//  Purpose : if cache miss, get the web server response data and save cache file    //
///////////////////////////////////////////////////////////////////////////////////////

void reqWebResClnt(int web_sock_fd, int clnt_fd, char *request_msg, char *hashed_url)
{
  char response_buf[BUF_SIZE] = {0, };
  int cache_fd,read_len;

  if(0 > (cache_fd = open(hashed_url+3, O_RDWR | O_CREAT | O_APPEND, 0777))){puts("can't open file in reqWebResClnt()\n");}

  write(web_sock_fd, request_msg, strlen(request_msg));
  #if defined(_DEBUG_)
  printf("MISS Send Web : %s\n===============\n", request_msg);
  #endif

  alarm(10);  //if no response while 10 sec, program response '응답없음'
  while(0 < (read_len = read(web_sock_fd, response_buf, BUF_SIZE))){
    #if defined(_DEBUG_)
    printf("MISS Receive Web: %s\n=============\n", response_buf);
    #endif
    write(cache_fd, response_buf, read_len);
    write(clnt_fd, response_buf, read_len);
    alarm(0);
  }
  close(cache_fd);
}
///////////////////////////////////////////////////////////////////////////////////
//  resClnt                                                                      //
//  ==========================                                                   //
//  int clnt_sock_fd -> client socket file descrypter                            //
//  char *src_url -> hashed input url                                            //
//  ==========================                                                   //
//  Purpose : if cache hit, response cache file to client                        //
///////////////////////////////////////////////////////////////////////////////////

void resClnt(int clnt_sock_fd, char *src_url) //if hit, proxy response to clnt that it have cache file
{
  char buf[BUF_SIZE] = {0, };
  DIR *pDir = NULL;
  struct dirent *pFile = NULL;
  int cache_fd, read_len;

  if(0 > (cache_fd = open(src_url+3, O_RDONLY))){puts("can't open file in resClnt()");}

  #if defined(_DEBUG_)
    printf("Hit response : \n");
  #endif

  while(0 < (read_len = read(cache_fd, buf, BUF_SIZE))){
    write(clnt_sock_fd, buf, read_len);
    #if defined(_DEBUG_)
      printf("%s\n===================\n", buf);
    #endif
  }
}
///////////////////////////////////////////////////////////////////////////////////
//  requestParsedHostURL                                                         //
//  ================================                                             //
//  char *request -> request message from client                                 //
//  char *urlBuf -> extract host url buffer                                      //
//  ================================                                             //
//  Purpose : extract host url at client request message                         //
///////////////////////////////////////////////////////////////////////////////////

char *requestParsedHostURL(char *request, char *urlBuf)
{
  char tmp[BUF_SIZE] = {0,};
  char method[20] = {0,};
  char *tok;
  strcpy(tmp, request);
  tok = strtok(tmp, " ");
  strcpy(method, tok);
  if(0 == strcmp(method, "GET") ||
    0 == strcmp(method, "POST") ||
    0 == strcmp(method, "CONNECT")){
    tok = strtok(NULL, " ");  //http://www.~~~.~~~
    tok = strtok(tok, "/");
    tok = strtok(NULL, "/");
    strcpy(urlBuf, tok);
  }
  return urlBuf;
}
///////////////////////////////////////////////////////////////////////////////////
//  requestParsedFullURL                                                         //
//  ====================================                                         //
//  char *request -> request message from client                                 //
//  char *urlBuf -> extract Full url buffer                                      //
//  ====================================                                         //
//  Purpose : extract host url at client request message                         //
///////////////////////////////////////////////////////////////////////////////////

char *requestParsedFullURL(char *request, char *urlBuf)
{
  char tmp[BUF_SIZE] = {0, };
  char method[20] = {0, };
  char *tok;
  strcpy(tmp, request);
  strtok(tmp, " ");   //"GET"
  tok = strtok(NULL, " ");  //tok = "http://www.~~~.~~"

  strcpy(tmp, tok); //tmp = http://www.~~~.~~~ + message block
  tok = strtok(tmp, "/");
  tok = strtok(NULL, " ");  //tok = "/www.~~~.~~~"
  strcpy(urlBuf, tok + 1);  //tok + 1 = "www.~~~.~~~"
  return urlBuf;
}
///////////////////////////////////////////////////////////////////////////////////
//  getIPAddr                                                                    //
//  ==========================                                                   //
//  char *addr -> host url                                                       //
//  ==========================                                                   //
//  Purpose : change host url to dotted decimal type                             //
///////////////////////////////////////////////////////////////////////////////////

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
  char host_url[DIR_LEN] = {0, };
  char *input_url = 0, *hashed_url = 0;
  char temp[DIR_LEN] = "/cache", path[DIR_LEN], logPath[DIR_LEN]="/logfile";  //concaternate for root dir name var
  CACHE_ATTR cache_attr;
  pid_t child_pid;
  FILE *log_fp = 0;
  DIR *pDir = NULL;

  //socket variable
  int clnt_fd, serv_fd, addr_len = 0;
  struct sockaddr_in serv_addr, clnt_addr;
  char clnt_ip[BUF_SIZE] = {0, }, msg[BUF_SIZE] = {0, };

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
  gcache_attr = cache_attr;

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
  gst_handler.log_fp = log_fp;
  gst_handler.state = STAT_SERV;

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
  signal(SIGCHLD, (void *)sigchld_handler);
  signal(SIGINT, (void *)sigint_handler);
  signal(SIGALRM, (void *)sigalarm_handler);

  while(1){
    memset(&clnt_addr, 0, sizeof(clnt_addr));
    memset(clnt_ip, 0, sizeof(clnt_ip));
    addr_len = sizeof(clnt_addr);
    clnt_fd = accept(serv_fd, (struct sockaddr*)&clnt_addr, &addr_len);
    gst_handler.clnt_fd = clnt_fd;

    if(0 > (child_pid = fork())){
      fputs("can't make process.\n", stderr);
      close(clnt_fd);
      close(serv_fd);
      fclose(log_fp);
      break;
    }else if(0 == child_pid){ //child logic
      gst_handler.state = STAT_CHILD;

      time(&cache_attr.start);
      strncpy(clnt_ip, inet_ntoa(clnt_addr.sin_addr), strlen(inet_ntoa(clnt_addr.sin_addr)));
      #if defined(_DEBUG_)
      printf("[%s : %d] client was connected\n", clnt_ip, ntohs(clnt_addr.sin_port));
      #endif
      while(0 < read(clnt_fd, msg, BUF_SIZE)){

        #if defined(_DEBUG_)
        printf("request from client : \n%s\n==========\n", msg);
        #endif

        //Parsed URL logic
        requestParsedHostURL(msg, host_url); //extract host url from request msg
        requestParsedFullURL(msg, input_url);
        //hit miss logic
        if(0 == sha1_hash(input_url, hashed_url))
          fputs("sha1_hash() failed\n", stderr);

        strcpy(gcache_attr.input_url, input_url);
        strcpy(gcache_attr.hashed_url, hashed_url);

        if(DEF_MISS == isHit(hashed_url)){
          //if cache miss, proxy request to web server
          //so, Make socket, request http format message
          #if defined(_DEBUG_)
          printf("MISS logic\n");
          #endif
          char *ip_addr = getIPAddr(host_url);
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
          cache_attr.miss += 1;
          cache_attr.flag = DEF_MISS;

          gcache_attr = cache_attr;

          makeDir(hashed_url);

          if(0 > changeDir(hashed_url)){fputs("changeDir() error\n", stderr); break;}  //cd ~/caache/ef0
          reqWebResClnt(web_sock_fd, clnt_fd, msg, hashed_url);
          close(web_sock_fd);
        }else{
          cache_attr.hit += 1;
          cache_attr.flag = DEF_HIT;

          gcache_attr = cache_attr;

          //hit response
          if(0 > changeDir(hashed_url)){fputs("changeDir() error\n", stderr); break;}  //cd ~/caache/ef0
          resClnt(clnt_fd, hashed_url);
        }
        chdir(path);  //cd ~/cache/
        if(STAT_LOG == reqFilter(msg))
          writeLogFile(input_url, hashed_url, &cache_attr, log_fp);
      }
      //when the child process has NO data to receive
      #if defined(_DEBUG_)
      printf("[%s : %d] client was disconnected\n", clnt_ip, ntohs(clnt_addr.sin_port));
      #endif
      close(clnt_fd);
      close(serv_fd);
      fclose(log_fp);
      break;
    }else{  //parent logic
      //control child process list
      //write log
      //count of child process
      cache_attr.numofchild += 1;
      gcache_attr = cache_attr;
      //closing file descrypter
    }

  }
  if(input_url) free(input_url);
  if(hashed_url) free(hashed_url);
  #if defined(_DEBUG_)
  printf("child process end\n");
  #endif
  return 0;
}
