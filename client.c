#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define BUFSIZE   256
#define PORTNO    40000
#define CLT_ADDR  "127.0.0.1"

int main(int argc, char *argv[])
{
  int sock_fd, len;
  struct sockaddr_in server_addr;
  char buf[BUFSIZE] = CLT_ADDR;
  char haddr[] = CLT_ADDR;
  char input_url[BUFSIZE];
  if(0 > (sock_fd = socket(PF_INET, SOCK_STREAM, 0))){
    fputs("can't create socket.\n", stderr);
    return -1;
  }
  memset(buf, 0, sizeof(buf));
  memset((char*)&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = inet_addr(haddr);
  //server_addr.sin_port = htons(PORTNO);
  server_addr.sin_port = htons(PORTNO);
  if(0 > connect(sock_fd, (struct sockaddr*)&server_addr, sizeof(server_addr))){
    fputs("can't connect.\n", stderr);
    return -1;
  }
  while(1){
    printf("input url > ");
    scanf("%s", input_url);
    if(0 == strcmp(input_url, "bye")){
      write(sock_fd, input_url, BUFSIZE);
      close(sock_fd);
      return 1;
    }
    write(sock_fd, input_url, BUFSIZE);
    len = BUFSIZE;
    while(0 < len){
      len -= read(sock_fd, buf, BUFSIZE);
      printf("%s\n", buf);
    }
  }
  return 0;
}
