#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/fcntl.h>

int main(int argc, char *argv[])
{
	int i = 0;
	int byteCount = 1;
	char c = 0;

	int randFile = 0;

	if(argc == 2)
		byteCount = atoi(argv[1]);
	
	randFile = open("/dev/random", O_RDONLY);
	if(!randFile)
	{
		printf("Unable to open /dev/random\n");
		return 1;
	}

	for(i = 0; i < byteCount; i++)
	{
		read(randFile, &c, 1);
		printf("%i, ", c);
	}

	close(randFile);
	randFile = 0;

	printf("\n");

	return 0;
}

