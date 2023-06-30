#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>

// all the best !! :)
void win(){
	char flag[100];
	const int fd = open("./flag.txt", O_RDONLY);

	if (fd < 0){
		fprintf(stdout, "if this happens on the server, talk to admin, else create a flag.txt file :)");
		fflush(stdout);
	}

	read(fd, flag, sizeof(flag));
	fprintf(stdout, "%s \n", flag);
	fflush(stdout);
}

void welcome_message(){
	fprintf(stdout, "Welcome to the Madness Comrade !\n");
	fflush(stdout);
}

int main(int argc, char **argv){
	void (*f)() = welcome_message;
	char buff[2];
	printf("Do you have anything to say? (y\\n): ");
	fflush(stdout);
	scanf("%s", buff);
	f();
	return 0;
}
