#define SIZE 4096
#define RED "\e[0;31m"
#define BRED "\e[1;31m"
#define reset "\e[0m"
#define URED "\e[4;31m"
#define BHRED "\e[1;91m"
#define BHGRN "\e[1;92m"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <openssl/sha.h>
#include <termios.h>
#include <malloc.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/ssl.h>

char* dStrs[] = {"-d", "--debug"};

/* argv the char** must have the char*'s terminated by a NULL */
int isContainedIn(char** haystack, char* needle);

int checkDebug(char** arr);
void combineArgs(char* destination, const int argc, char** argv);

// Credit to David C. Rankin
ssize_t getpasswd (char **pw, size_t sz, int mask, FILE *fp);

void getHashStrs(char* hashStrDest, char* firstFiveStrDest, const char* hashData);
int hasNonDebugArg(char** arr);
int strEqStopAt(char* strOne, char* strTwo, char stopAt);
void hostname_to_ip(char *hostname , char *ip);

int main(int argc, char** argv){

	/* Make an array of arguments, not including executable name and including a terminating NULL */
	char* args[argc];
	for(int i = 1; i < argc; i++)
		args[i - 1] = argv[i];
	args[argc - 1] = NULL;

	int debug = checkDebug(args); // for debug mode

	char pass[SIZE];

	if(argc > 1 && hasNonDebugArg(args)){
		// The password to check was provided in the arguments

		combineArgs(pass, argc, argv);
	}else{
		// Will use stdin to get the password
		// This will not work with piping, however. The user must type it in

		puts("Note that your password is hashed locally before it is \"sent\" to pwnedpasswords.com. Additionally, only the first 5 hexbits (20 bits out of 160 total) of your hash are sent. The source code will be publicly available soon.");
		fputs("Enter your password here: ", stdout);

		char* tmp = pass; // the getpasswd function (by Rankin) seems to require this
		getpasswd(&tmp, SIZE, 42, stdin);

		puts(""); // these are just for the \n to stdout
	}

	if(debug) printf("(debug) Using '%s' as the password to check.\n", pass);	

	char hash[SHA_DIGEST_LENGTH];
	SHA1(pass, strlen(pass), hash);

	char firstFiveHashStr[6]; // null char
	char hashStr[SIZE];
	getHashStrs(hashStr, firstFiveHashStr, hash);

	if(debug){
		printf("(debug) hashStr is '%s'\n", hashStr);
		printf("(debug) firstFiveHashStr is '%s'\n", firstFiveHashStr);
	}

	char url[SIZE];
	sprintf(url, "https://api.pwnedpasswords.com/range/%s", firstFiveHashStr); // we will send HTTP GET here


	int sock = 0;
	struct sockaddr_in servAddr;
	char* fmt = "GET /range/%s HTTP/1.1\nHost: api.pwnedpasswords.com\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\nAccept-Language: en-US,en;q=0.5\nConnection: keep-alive\r\n\r\n";
	char toSend[strlen(fmt) + 6];
	sprintf(toSend, fmt, firstFiveHashStr);

	char buf[SIZE];
	memset(buf, '\0', SIZE);

	if((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0){
		fputs("\nSocket creation error!!\n", stderr);
	}
	servAddr.sin_family = AF_INET;
	servAddr.sin_port = htons(443);

	char* hostname = "api.pwnedpasswords.com";

	char ip[100];
	hostname_to_ip(hostname, ip);

	if(debug) printf("(debug) hostname '%s' was resolved to IP: %s\n", hostname, ip);

	// Convert IPv4 and IPv6 addresses from text to binary form
    if(inet_pton(AF_INET, ip, &servAddr.sin_addr) <= 0) 
    {
        fputs("\nInvalid address/ Address not supported \n", stderr);
        return -1;
    }

	int connRes = 999;
	if ((connRes = connect(sock, (struct sockaddr *)&servAddr, sizeof(servAddr))) < 0)
    {
        fputs("\nConnection Failed \n", stderr);
		printf("connRes: %d\n", connRes);
        return -1;
    }

	// using SSL as the pwnedpasswords website redirects all HTTP to HTTPS with a 301 response

	/* <CODE_FROM href="https://newbedev.com/make-an-https-request-using-sockets-on-linux"> */

	// initialize OpenSSL - do this once and stash ssl_ctx in a global var
	SSL_load_error_strings();
	SSL_library_init();
	SSL_CTX* ssl_ctx = SSL_CTX_new (SSLv23_client_method());

	// create an SSL connection and attach it to the socket
	SSL* conn = SSL_new(ssl_ctx);
	SSL_set_fd(conn, sock);

	// perform the SSL/TLS handshake with the server - when on the
	// server side, this would use SSL_accept()
	int err = SSL_connect(conn);
	if (err != 1) abort(); 

	/* </CODE_FROM> */

	char finalBuf[999999] = "";
	
	SSL_write(conn, toSend, strlen(toSend));

	int received;
	while(1){
		received = SSL_read(conn, buf, SIZE);

		if(received == 5)
			break;

		if(received == 0) break; // this does not seem to happen with pwnedpasswords.com
		else if(received < 0){
			int error = SSL_get_error(conn, received);

			if(error == SSL_ERROR_WANT_READ){
				int s = SSL_get_rfd(conn);

				struct timeval timeout;
				timeout.tv_sec = 5;

				error = select(sock + 1, NULL, NULL, NULL, &timeout);
				if(error > 0) continue;
			}
		}

		strcat(finalBuf, buf); // apend received data to our big buffer
		memset(buf, 0x0, SIZE); // reset small buffer
	}

	SSL_free(conn);
	
	char* httpOkLoc;
	if(debug && (httpOkLoc = strstr(finalBuf, "200 OK")) != NULL && httpOkLoc - finalBuf < 10){
		puts("(debug) Client (this program) received an HTTP response of 200 OK. Our request was correctly sent and a response was received.");
	}

	char* res = strstr(finalBuf, "Server:");
	res = strstr(res, "\r\n\r\n");
	char* firstColon = strchr(res, ':');

	if(*(firstColon - 36) == '\n') res = firstColon - 35;
	else printf("hmm the firstColon - 36 points to character '%c'\n", *(firstColon - 36));

	int hashFound = 0;
	for(char* tok = strtok(res, "\r\n"); tok != NULL; tok = strtok(NULL, "\r\n")){
		if(strchr(tok, ':') == NULL) continue;

		if(strEqStopAt(tok, hashStr + 5, ':')){
			hashFound = 1;
			int n;
			sscanf(strchr(tok, ':') + 1, "%d", &n);

			if(debug) printf("(debug) provided password's unique hash was found in a public database leak like so: %s\n", tok);
			
			fprintf(stderr, "%sYou NEED to change your password as it's hash (unique to your pass) was found on public database leaks %s%d%s times!\n%s", BRED, BHRED, n, BRED, reset);
		}
	}

	if(!hashFound){
		fprintf(stderr, "%sGood news! Your password hash was not found on the public leaks listed at pwnedpasswords.com!\n%s", BHGRN, reset);
		fputs("Note that this does not assure safety, or that your password hash was not leaked elsewhere.\n", stderr);
	}
}

int isContainedIn(char** haystack, char* needle){
	for(char** i = haystack; *i != NULL; i++) if(!strcmp(needle, *i)) return 1;
	
	return 0;
}

int checkDebug(char** arr){
	for(char** i = arr; *i != NULL; i++)
		if(isContainedIn(dStrs, *i)) return 1;
	
	return 0;
}

void combineArgs(char* destination, const int argc, char** argv){
	unsigned int left = SIZE;

	for(int i = 1; i < argc; i++)
		if(!isContainedIn(dStrs, argv[i])){
			strncat(destination, argv[i], left);
			strncat(destination, " ", 1);
			left = SIZE - strlen(destination);
		}

	destination[strlen(destination) - 1] = 0x0;
}

/* read a string from fp into pw masking keypress with mask char.
getpasswd will read upto sz - 1 chars into pw, null-terminating
the resulting string. On success, the number of characters in
pw are returned, -1 otherwise.
*/
ssize_t getpasswd (char **pw, size_t sz, int mask, FILE *fp){
    if (!pw || !sz || !fp) return -1;       /* validate input */
	#ifdef MAXPW
		if (sz > MAXPW) sz = MAXPW;
	#endif

    if (*pw == NULL) {              		/* reallocate if no address */
        void *tmp = realloc (*pw, sz * sizeof **pw);
        if (!tmp)
            return -1;
        memset (tmp, 0, sz);    			/* initialize memory to 0 */
        *pw =  (char*) tmp;
    }

    size_t idx = 0;         				/* index, number of chars in read */
    int c = 0;

    struct termios old_kbd_mode;   		 	/* orig keyboard settings */
    struct termios new_kbd_mode;

    if (tcgetattr (0, &old_kbd_mode)) { 	/* save orig settings */
        fprintf (stderr, "%s() error: tcgetattr failed.\n", __func__);
        return -1;
    }   /* copy old to new */
    memcpy (&new_kbd_mode, &old_kbd_mode, sizeof(struct termios));

    new_kbd_mode.c_lflag &= ~(ICANON | ECHO);  /* new kbd flags */
    new_kbd_mode.c_cc[VTIME] = 0;
    new_kbd_mode.c_cc[VMIN] = 1;
    if (tcsetattr (0, TCSANOW, &new_kbd_mode)) {
        fprintf (stderr, "%s() error: tcsetattr failed.\n", __func__);
        return -1;
    }

    /* read chars from fp, mask if valid char specified */
    while (((c = fgetc (fp)) != '\n' && c != EOF && idx < sz - 1) ||
            (idx == sz - 1 && c == 127))
    {
        if (c != 127) {
            if (31 < mask && mask < 127)    /* valid ascii char */
                fputc (mask, stdout);
            (*pw)[idx++] = c;
        }
        else if (idx > 0) {         /* handle backspace (del) */
            if (31 < mask && mask < 127) {
                fputc (0x8, stdout);
                fputc (' ', stdout);
                fputc (0x8, stdout);
            }
            (*pw)[--idx] = 0;
        }
    }
    (*pw)[idx] = 0; /* null-terminate   */

    /* reset original keyboard  */
    if (tcsetattr (0, TCSANOW, &old_kbd_mode)) {
        fprintf (stderr, "%s() error: tcsetattr failed.\n", __func__);
        return -1;
    }

    if (idx == sz - 1 && c != '\n') /* warn if pw truncated */
        fprintf (stderr, " (%s() warning: truncated at %zu chars.)\n",
                __func__, sz - 1);

    return idx; /* number of chars in passwd */
}

void getHashStrs(char hashStrDest[], char* firstFiveStrDest, const char* hashData){
	memset(firstFiveStrDest, 0, 6);
	memset(hashStrDest, 0, SIZE);

	for(short fiveCount = 0; *hashData; fiveCount++){
		if(fiveCount <= 20) sprintf(hashStrDest + strlen(hashStrDest), "%02X", (unsigned int) *hashData);
		if(fiveCount < 3) sprintf(firstFiveStrDest + strlen(firstFiveStrDest), "%02X", (unsigned int) *hashData);

		hashData++;
	}

	// truncate to five hex bits
	// firstFiveStrDest[5] = 0x0;
	memset(firstFiveStrDest + 5, 0, SIZE - 5);

	// truncate to first 40 hex bits
	memset(hashStrDest + 40, 0, SIZE - 40);
}

int hasNonDebugArg(char** arr){
	for(char** i = arr; *i != NULL; i++)
		if(!isContainedIn(dStrs, *i)) return 1;
	
	return 0;
}

int strEqStopAt(char* strOne, char* strTwo, char stopAt){
	for(char* one = strOne, *two = strTwo; *one != 0x0; ){
		
		if(*one != ':' && *two != ':'){
			if(*one != *two) return 0;
		}
		else return 1;
		
		one++; 
		two++;
	}
	
	return 1;
}

void hostname_to_ip(char* hostname, char* ip)
{
	int sockfd, rv;  
	struct addrinfo hints, *servinfo, *p;
	struct sockaddr_in* h;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC; 
	hints.ai_socktype = SOCK_STREAM;

	if ((rv = getaddrinfo(hostname, "http", &hints, &servinfo)) != 0){
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return;
	}

	for(p = servinfo; p != NULL; p = p->ai_next)
	{
		h = (struct sockaddr_in*) p->ai_addr;
		char* tmp = inet_ntoa(h->sin_addr);

		if(strcmp("0.0.0.0", tmp)) strcpy(ip, tmp);
	}

	freeaddrinfo(servinfo);
}
