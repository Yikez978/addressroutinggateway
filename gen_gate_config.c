// This file is largely stolen from PolarSSL's rsa_keygen.c
#ifndef _CRT_SECURE_NO_DEPRECATE
#define _CRT_SECURE_NO_DEPRECATE 1
#endif

#include <stdio.h>

#include "polarssl/config.h"

#include "polarssl/entropy.h"
#include "polarssl/ctr_drbg.h"
#include "polarssl/bignum.h"
#include "polarssl/x509.h"
#include "polarssl/rsa.h"

#include "settings.h"

#define KEY_SIZE (RSA_KEY_SIZE * 8)
#define EXPONENT 65537

int main( int argc, char *argv[] )
{
	char name[MAX_NAME_SIZE];
	char baseIP[20];
	char mask[20];

	char pubKeyName[MAX_CONF_LINE];
	char privKeyName[MAX_CONF_LINE];

    int ret;
    rsa_context rsa;
    entropy_context entropy;
    ctr_drbg_context ctr_drbg;
    FILE *fpub  = NULL;
    FILE *fpriv = NULL;
    char *pers = "rsa_genkey";

    ((void) argc);
    ((void) argv);

	// Get data we need
	if(argc == 4)
	{
		strncpy(name, argv[1], sizeof(name));
		strncpy(baseIP, argv[2], sizeof(baseIP));
		strncpy(mask, argv[3], sizeof(mask));
	}
	else
	{
		printf("Usage: %s <name> <base ip> <mask>\n", argv[0]);
		return 1;
	}

    printf( "\n  . Seeding the random number generator..." );
    fflush( stdout );

    entropy_init( &entropy );
    if( ( ret = ctr_drbg_init( &ctr_drbg, entropy_func, &entropy,
                               (unsigned char *) pers, strlen( pers ) ) ) != 0 )
    {
        printf( " failed\n  ! ctr_drbg_init returned %d\n", ret );
        goto exit;
    }

    printf( " ok\n  . Generating the RSA key [ %d-bit ]...", KEY_SIZE );
    fflush( stdout );

    rsa_init( &rsa, RSA_PKCS_V15, 0 );
    
    if( ( ret = rsa_gen_key( &rsa, ctr_drbg_random, &ctr_drbg, KEY_SIZE,
                             EXPONENT ) ) != 0 )
    {
        printf( " failed\n  ! rsa_gen_key returned %d\n\n", ret );
        goto exit;
    }

	// Write public data
	snprintf(pubKeyName, sizeof(pubKeyName), "%s.pub", name);
	printf( " ok\n  . Exporting the public  key in %s....", pubKeyName );
    fflush( stdout );

    if( ( fpub = fopen( pubKeyName, "wb+" ) ) == NULL )
    {
        printf( " failed\n  ! could not open rsa_pub.txt for writing\n\n" );
        ret = 1;
        goto exit;
    }

	fprintf(fpub, "%s\n", baseIP);
	fprintf(fpub, "%s\n", mask);

    if( ( ret = mpi_write_file( "N = ", &rsa.N, 16, fpub ) ) != 0 ||
        ( ret = mpi_write_file( "E = ", &rsa.E, 16, fpub ) ) != 0 )
    {
        printf( " failed\n  ! mpi_write_file returned %d\n\n", ret );
        goto exit;
    }

	// Write private key file
	snprintf(privKeyName, sizeof(pubKeyName), "%s.priv", name);
	
	printf( " ok\n  . Exporting the private key in %s...", privKeyName );
    fflush( stdout );

    if( ( fpriv = fopen( privKeyName, "wb+" ) ) == NULL )
    {
        printf( " failed\n  ! could not open rsa_priv.txt for writing\n" );
        ret = 1;
        goto exit;
    }

    if( ( ret = mpi_write_file( "N = " , &rsa.N , 16, fpriv ) ) != 0 ||
        ( ret = mpi_write_file( "E = " , &rsa.E , 16, fpriv ) ) != 0 ||
        ( ret = mpi_write_file( "D = " , &rsa.D , 16, fpriv ) ) != 0 ||
        ( ret = mpi_write_file( "P = " , &rsa.P , 16, fpriv ) ) != 0 ||
        ( ret = mpi_write_file( "Q = " , &rsa.Q , 16, fpriv ) ) != 0 ||
        ( ret = mpi_write_file( "DP = ", &rsa.DP, 16, fpriv ) ) != 0 ||
        ( ret = mpi_write_file( "DQ = ", &rsa.DQ, 16, fpriv ) ) != 0 ||
        ( ret = mpi_write_file( "QP = ", &rsa.QP, 16, fpriv ) ) != 0 )
    {
        printf( " failed\n  ! mpi_write_file returned %d\n\n", ret );
        goto exit;
    }
    
	printf( " ok\n\n" );

exit:

    if( fpub  != NULL )
        fclose( fpub );

    if( fpriv != NULL )
        fclose( fpriv );

    rsa_free( &rsa );

    return( ret );
}

