#include "simeckr.h"

#include <termios.h>
#include <time.h>
#include <sys/stat.h>
#include <unistd.h>
#include <ctype.h>

int isStrongPassword(const char *password) {
    int length = strlen(password);

    // Criteria for a strong password
    int hasUpper = 0;
    int hasLower = 0;
    int hasDigit = 0;
    int hasSpecial = 0;

    // Check each character of the password
    for (int i = 0; i < length; i++) {
        if (isupper(password[i])) {
            hasUpper = 1;
        } else if (islower(password[i])) {
            hasLower = 1;
        } else if (isdigit(password[i])) {
            hasDigit = 1;
        } else if (ispunct(password[i])) {
            hasSpecial = 1;
        }
    }

    // Password is strong if all criteria are met
    return length >= 10 && hasUpper && hasLower && hasDigit && hasSpecial;
}

int main(int argc, char *argv[]) {
    
    // get input file and out file names
	if (argc != 4) {
		fprintf(stderr, "Usage: %s input-filename output-filename rounds(7)\n", argv[0]);
		return 0;
    }

    // check if input file exists
    struct stat statbuf;
    if (stat(argv[1], &statbuf) == -1) {
	    perror("stat()");
	    return 1;
    }

    // read password without printing echo bytes on screen
    char passwd[MAXPWDLEN];
    struct termios original,noecho;

    tcgetattr(STDIN_FILENO, &original);
    noecho = original;
    noecho.c_lflag = noecho.c_lflag ^ ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &noecho);
    printf("Password: ");
    fgets(passwd, MAXPWDLEN, stdin);
    fprintf(stdout, "\n");
    uint32_t pwdlen = strlen((char *)passwd);
    passwd[pwdlen-1] = '\0';
    pwdlen--;
    tcsetattr(STDIN_FILENO, TCSANOW, &original);

    // check password strength
    if (!isStrongPassword(passwd)) {
        fprintf(stderr, "Weak password.\n Use uppercase, lowercase, digits and special chars -- at least 10 bytes long.\n");
        return (10);
    }	 

    simeckr_ctx CTX;
    SimeckInit(&CTX, passwd);

    // read input file
    FILE *fp, *fpout;
    off_t fsize = statbuf.st_size;
    fpout = fopen(argv[2], "w");
    if (fpout == NULL) {
	    perror("fopen() for writing");
	    return 3;
    }
    fp = fopen(argv[1], "rb+");
    if (fp == NULL) {
        perror("fopen() for reading");
        return 2;
    }

    uint32_t plaintext[2], ciphertext[2];
    SIMECK_R_ROUNDS = strtol(argv[3], NULL, 10); // default is 7

    int ret = 8;
    while(ret == 8) {
       if ((ret = fread(plaintext, 1, 8, fp))==0) { // read 64 bits
	        if (ferror(fp)) {
	            perror("fread()");
        	    exit(EXIT_FAILURE);
	        }
        }

        SimeckREncrypt(plaintext, ciphertext, &CTX);
       
        if (fwrite(ciphertext, 8, 1, fpout)!=1) { // write 64 bits of ciphertext
            perror("fwrite()");
            exit(EXIT_FAILURE);
        }
    }

    fclose(fp); 
    fclose(fpout);

    /*
     * if we read less than 8 bytes because filesize is not a multiple of 64 bits
     * we need to truncate to original filesize since surplus encrypted bits are
     * not from the original plaintext but dummy bytes
     */
    if (truncate(argv[2], fsize) == -1) {
	    perror("truncate() output file");
	    exit(EXIT_FAILURE);
    }
  
    return 0;
}
