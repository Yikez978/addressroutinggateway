#include <dirent.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#include "settings.h"
#include "utility.h"
#include "hopper.h"

char read_config(struct config_data *conf)
{
	char line[MAX_CONF_LINE];
	FILE *confFile = NULL;
	
	char *dirPathEnd;
	int dirLen;
	DIR *confDir = NULL;

	int len;
	struct dirent *dent = NULL;

	struct gate_list *currGate = NULL;
	struct gate_list *prevGate = NULL;

	// Find the directory the configuration file is in
	dirPathEnd = strrchr(conf->file, '/');
	if(dirPathEnd == NULL)
		dirPathEnd = strrchr(conf->file, '\\');
	
	if(dirPathEnd != NULL)
	{
		dirLen = (long)dirPathEnd - (long)&conf->file;
		strncpy(conf->dir, conf->file, dirLen);
		conf->dir[dirLen] = '\0';
	}
	else
		strncpy(conf->dir, ".", sizeof(conf->dir));

	// Read through the file
	arglog(LOG_DEBUG, "Reading from configuration file %s\n", conf->file);
	confFile = fopen(conf->file, "r");
	if(confFile == NULL)
	{
		arglog(LOG_DEBUG, "Unable to open config file at %s\n", conf->file);
		return -1;
	}

	if(get_next_line(confFile, line, MAX_CONF_LINE))
	{
		arglog(LOG_DEBUG, "Problem reading in gate name from conf\n");
		fclose(confFile);
		return -2;
	}
	strncpy(conf->ourGateName, line, sizeof(conf->ourGateName));

	if(get_next_line(confFile, line, MAX_CONF_LINE))
	{
		arglog(LOG_DEBUG, "Problem reading in hop rate from conf\n");
		fclose(confFile);
		return -2;
	}
	conf->hopRate = atol(line);

	fclose(confFile);
	confFile = NULL;

	// Get the names of all the public key files listed alongside the conf file
	confDir = opendir(conf->dir);
	if(confDir == NULL)
	{
		arglog(LOG_DEBUG, "Unable to open the directory (%s) that contains the config file\n", conf->dir);
		return -1;
	}

	conf->gate = NULL;
	dent = readdir(confDir);
	for(;;)
	{
		dent = readdir(confDir);
		if(!dent)
			break;

		// Skip hidden files, ., and ..
		len = strlen(dent->d_name);
		if(dent->d_name[0] == '.' || len < 5)
			continue;

		// Must end in .pub
		if(strncmp(&dent->d_name[len - 4], ".pub", 4) != 0)
			continue;

		// Found one!
		prevGate = currGate;
		currGate = (struct gate_list*)calloc(sizeof(struct gate_list), 1);
		if(currGate == NULL)
		{
			arglog(LOG_DEBUG, "Unable to allocate space to read in gate public key list\n");
			continue;
		}
		
		if(conf->gate == NULL)
			conf->gate = currGate;

		if(prevGate != NULL)
			prevGate->next = currGate;

		strncpy(currGate->name, dent->d_name, len - 4);
		currGate->name[len - 4] = '\0';
		
		arglog(LOG_DEBUG, "Found public key for gate %s\n", currGate->name);
	}

	currGate->next = NULL;

	closedir(confDir);
	confDir = NULL;

	return 0;
}

void release_config(struct config_data *conf)
{
	struct gate_list *curr = NULL;
	struct gate_list *prev = NULL;

	curr = conf->gate;
	while(curr)
	{
		prev = curr;
		curr = curr->next;
		free(prev);
	}
}

char read_public_key(struct config_data *conf, struct arg_network_info *gate)
{
	int ret;
	char line[MAX_CONF_LINE] = "";
	char path[MAX_CONF_LINE] = "";
	FILE *keyFile = NULL;

	// Read in key
	snprintf(path, sizeof(path), "%s/%s.pub", conf->dir, gate->name);
	keyFile = fopen(path, "r");
	if(keyFile == NULL)
	{
		arglog(LOG_DEBUG, "Unable to open public key file at %s\n", path);
		return -1;
	}

	// Start of data is our IP and mask
	if(get_next_line(keyFile, line, MAX_CONF_LINE))
	{
		arglog(LOG_DEBUG, "Problem reading in IP from private file\n");
		fclose(keyFile);
		return -2;
	}
	inet_pton(AF_INET, line, gate->baseIP); 
	
	if(get_next_line(keyFile, line, MAX_CONF_LINE))
	{
		arglog(LOG_DEBUG, "Problem reading in mask from private file\n");
		fclose(keyFile);
		return -2;
	}
	inet_pton(AF_INET, line, gate->mask);
	
	// Then the actual numbers for the key
	if((ret = mpi_read_file(&gate->rsa.N, 16, keyFile)) != 0 ||
		(ret = mpi_read_file(&gate->rsa.E, 16, keyFile)) != 0)
	{
		arglog(LOG_DEBUG, "Unable to read in public key for %s (returned %i)\n", gate->name, ret);
		return -1;
	}

	gate->rsa.len = (mpi_msb(&gate->rsa.N) + 7) >> 3;	

	fclose(keyFile);

	return 0;
}

char read_private_key(struct config_data *conf, struct arg_network_info *gate)
{
	int ret;
	FILE *privKeyFile = NULL;
	char path[MAX_CONF_LINE] = "";

	// Open private key
	snprintf(path, sizeof(path), "%s/%s.priv", conf->dir, gate->name);
	privKeyFile = fopen(path, "r");
	if(privKeyFile == NULL)
	{
		arglog(LOG_DEBUG, "Unable to open private key file at %s\n", path);
		return -1;
	}

	if( ( ret = mpi_read_file( &gate->rsa.N , 16, privKeyFile ) ) != 0 ||
		( ret = mpi_read_file( &gate->rsa.E , 16, privKeyFile ) ) != 0 ||
		( ret = mpi_read_file( &gate->rsa.D , 16, privKeyFile ) ) != 0 ||
		( ret = mpi_read_file( &gate->rsa.P , 16, privKeyFile ) ) != 0 ||
		( ret = mpi_read_file( &gate->rsa.Q , 16, privKeyFile ) ) != 0 ||
		( ret = mpi_read_file( &gate->rsa.DP, 16, privKeyFile ) ) != 0 ||
		( ret = mpi_read_file( &gate->rsa.DQ, 16, privKeyFile ) ) != 0 ||
		( ret = mpi_read_file( &gate->rsa.QP, 16, privKeyFile ) ) != 0 )
	{
		arglog(LOG_DEBUG, "Failed to load private key for ourselves (error %i)\n", ret);
		fclose(privKeyFile);
		return -1;
	}

	fclose(privKeyFile);
	privKeyFile = NULL;

	if((ret = rsa_check_privkey(&gate->rsa)) != 0)
	{
		arglog(LOG_DEBUG, "Private key check failed, error %i\n", ret);
		return -2;
	}

	return 0;
}

char get_next_line(FILE *f, char *line, int max)
{
	int len = 0;
	for(;;)
	{
		if(fgets(line, max, f) == NULL)
			return -1;

		if(line[0] != '\n' && line[0] != '\r')
		{
			len = strnlen(line, max);
			if(line[len - 1] == '\n')
				line[len - 1] = '\0';
			return 0;
		}
	}
}


