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
 * verify_trust(sig_file, data_file, gpg_home)
 *
 * returns 3 for ultimate trust,
 * returns 2 for full trust.
 * returns 1 for marginal trust.
 * returns 0 for no trust.
 * returns -1 for error.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <gpgme.h>
#include <string.h>
#include <argp.h>

const char *argp_program_version = "gpg-verify-trust 0.1";
const char *argp_program_bug_address = "mail@chris-stones.uk";
static char doc[] = "gpg-verify-trust -- check the trust level of the key used to sign a file.";
static char args_doc[] = "DATA_FILE_SIG  DATA_FILE";

static struct argp_option options[] = {
  {"homedir",   'H', "gpg_homedir", 0,  "GnuPG homedir." },
  { 0 }
};

struct arguments {
	const char * sigdir;
	const char * sigfile;
	const char * file;
};

static error_t parse_opt (int key, char *arg, struct argp_state *state)
{
  struct arguments *arguments = (struct arguments *)state->input;

  switch (key)
  {
  case 'H':
	  arguments->sigdir = arg;
	  break;
  case ARGP_KEY_ARG:
	if (state->arg_num == 0)
		arguments->sigfile = arg;
	else if (state->arg_num == 1)
		arguments->file = arg;
	else
		argp_usage (state);
	break;
  case ARGP_KEY_END:
	if (state->arg_num < 1)
	  argp_usage (state);
	break;
  default:
      return ARGP_ERR_UNKNOWN;
	  break;
  }
  return 0;
}

/***
 * Much code taken from _alpm_gpgme_checksig in pacman/lib/libalpm/signing.c
 * 	https://www.archlinux.org/pacman/
 */

static int gpgme_init(const char * sigdir) {

	gpgme_error_t gpg_err = 0;

	gpgme_check_version(NULL); // NOTE: initialises the library.

	// Require GPG engine.
	if((gpg_err = gpgme_engine_check_version(GPGME_PROTOCOL_OpenPGP)) != GPG_ERR_NO_ERROR)
		return gpg_err;

	if((gpg_err = gpgme_set_engine_info(GPGME_PROTOCOL_OpenPGP, NULL, sigdir))  != GPG_ERR_NO_ERROR)
		return gpg_err;

	return 0;
}

static int verify_trust(const char * sigpath, const char * path, const char * gpg_home) {

	int best_validity = -1;
	int sigcount;
	gpgme_error_t gpg_err = 0;
	gpgme_ctx_t ctx;
	gpgme_data_t filedata, sigdata;
	gpgme_verify_result_t verify_result;
	gpgme_signature_t gpgsig;
	FILE *file = NULL, *sigfile = NULL;
	int dev_null_fd = 0;

	memset(&ctx, 0, sizeof(ctx));
	memset(&sigdata, 0, sizeof(sigdata));
	memset(&filedata, 0, sizeof(filedata));

	if(gpgme_init(gpg_home) != GPG_ERR_NO_ERROR)
		goto error;

	sigfile = fopen(sigpath, "rb");

	if(path)
		file = fopen(path, "rb");
	else
		dev_null_fd = open("/dev/null", O_RDWR);


	if(!sigfile || (path && !file) || (!path && !dev_null_fd))
		goto error;

	gpg_err = gpgme_new(&ctx);

	/* create our necessary data objects to verify the signature */
	if(file)
		gpg_err = gpgme_data_new_from_stream(&filedata, file);
	else
		gpg_err = gpgme_data_new_from_fd(&filedata, dev_null_fd);

	/* file-based, it is on disk */
	gpg_err = gpgme_data_new_from_stream(&sigdata, sigfile);


	/* here's where the magic happens */
	gpg_err = gpgme_op_verify(
		ctx,
		sigdata,
		file ? filedata : NULL,
		file ? NULL     : filedata);

	verify_result = gpgme_op_verify_result(ctx);

	if(!verify_result || !verify_result->signatures)
		goto gpg_error;

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
	if(sigfile)
		fclose(sigfile);
	if(file)
		fclose(file);
	if(dev_null_fd)
		close(dev_null_fd);

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

	struct arguments _args;
	memset(&_args, 0, sizeof _args);

	static struct argp argp = { options, parse_opt, args_doc, doc };

	argp_parse (&argp, argc, argv, 0, 0, &_args);

	return verify_trust(_args.sigfile, _args.file, _args.sigdir);
}

