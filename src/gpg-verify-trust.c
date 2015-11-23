/*
 *  gpg-verify-trust.c
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * compile with gcc gpg-verify-trust.c -lgpgme -o verify_trust
 *
 * verify_trust(sig_file, data_file)
 *
 * returns 3 for ultimate trust,
 * returns 2 for full trust.
 * returns 1 for marginal trust.
 * returns 0 for no trust.
 * returns -1 for error.
 */


#include <gpgme.h>
#include <string.h>

/***
 * Much code taken from _alpm_gpgme_checksig in pacman/lib/libalpm/signing.c
 * 	https://www.archlinux.org/pacman/
 */

int verify_trust(const char * sigpath, const char * path) {

	int best_validity = -1;
	int sigcount;
	gpgme_error_t gpg_err = 0;
	gpgme_ctx_t ctx;
	gpgme_data_t filedata, sigdata;
	gpgme_verify_result_t verify_result;
	gpgme_signature_t gpgsig;
	FILE *file = NULL, *sigfile = NULL;

	memset(&ctx, 0, sizeof(ctx));
	memset(&sigdata, 0, sizeof(sigdata));
	memset(&filedata, 0, sizeof(filedata));

	sigfile = fopen(sigpath, "rb");

	file = fopen(path, "rb");

	if(!file || !sigfile)
		goto error;

	gpgme_check_version(NULL); // NOTE: initialises the library.

	gpg_err = gpgme_new(&ctx);

	/* create our necessary data objects to verify the signature */
	gpg_err = gpgme_data_new_from_stream(&filedata, file);

	/* file-based, it is on disk */
	gpg_err = gpgme_data_new_from_stream(&sigdata, sigfile);


	/* here's where the magic happens */
	gpg_err = gpgme_op_verify(ctx, sigdata, filedata, NULL);

	verify_result = gpgme_op_verify_result(ctx);

	if(!verify_result || !verify_result->signatures) {
		goto gpg_error;
	}

	for(gpgsig = verify_result->signatures, sigcount = 0; gpgsig;
				gpgsig = gpgsig->next, sigcount++) {


		if(gpg_err_code(gpgsig->status) == GPG_ERR_NO_ERROR)
		{
			int this_validity = 0;

			switch(gpgsig->validity) {
				case GPGME_VALIDITY_ULTIMATE:
					this_validity = 3;
					break;
				case GPGME_VALIDITY_FULL:
					this_validity = 2;
					break;
				case GPGME_VALIDITY_MARGINAL:
					this_validity = 1;
					break;
				case GPGME_VALIDITY_NEVER:
				case GPGME_VALIDITY_UNKNOWN:
				case GPGME_VALIDITY_UNDEFINED:
				default:
					break;
			}

			if(this_validity>best_validity)
				best_validity=this_validity;
		}
	}

gpg_error:
	gpgme_data_release(sigdata);
	gpgme_data_release(filedata);
	gpgme_release(ctx);

error:
	if(sigfile) {
		fclose(sigfile);
	}
	if(file) {
		fclose(file);
	}

	switch(best_validity) {
	case 0:
		printf("NOT TRUSTED (returning 0)\n");
		break;
	case 1:
		printf("MARGINAL TRUST (returning 1)\n");
		break;
	case 2:
		printf("FULL TRUST (returning 2)\n");
		break;
	case 3:
		printf("ULTIMATE_TRUST (returning 3)\n");
		break;
	default:
		printf("ERROR (returning %d)\n", best_validity);
	}

	return best_validity;
}


int main(int argc, char * argv[]) {

	if(argc==3)
		return verify_trust(argv[1],argv[2]);

	printf("useage: %s sig_file data_file\n", argv[0]);

	return -1;
}

