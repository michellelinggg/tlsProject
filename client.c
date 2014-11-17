/*
 * sig_client.c
 *
 * Author: Alec Guertin
 * University of California, Berkeley
 * CS 161 - Computer Security
 * Fall 2014 Semester
 * Project 1
 */

#include "client.h"

/* The file descriptor for the socket connected to the server. */
static int sockfd;

static void perform_rsa(mpz_t result, mpz_t message, mpz_t d, mpz_t n);
static int hex_to_ascii(char a, char b);
static int hex_to_int(char a);
static void usage();
static void kill_handler(int signum);
static int random_int();
static void cleanup();

int main(int argc, char **argv) {
  int err, option_index, c, clientlen, counter;
  unsigned char rcv_plaintext[AES_BLOCK_SIZE];
  unsigned char rcv_ciphertext[AES_BLOCK_SIZE];
  unsigned char send_plaintext[AES_BLOCK_SIZE];
  unsigned char send_ciphertext[AES_BLOCK_SIZE];
  aes_context enc_ctx, dec_ctx;
  in_addr_t ip_addr;
  struct sockaddr_in server_addr;
  FILE *c_file, *d_file, *m_file;
  ssize_t read_size, write_size;
  struct sockaddr_in client_addr;
  tls_msg err_msg, send_msg, rcv_msg;
  mpz_t client_exp, client_mod;
  fd_set readfds;
  struct timeval tv;

  c_file = d_file = m_file = NULL;

  mpz_init(client_exp);
  mpz_init(client_mod);

  /*
   * This section is networking code that you don't need to worry about.
   * Look further down in the function for your part.
   */

  memset(&ip_addr, 0, sizeof(in_addr_t));

  option_index = 0;
  err = 0;

  static struct option long_options[] = {
    {"ip", required_argument, 0, 'i'},
    {"cert", required_argument, 0, 'c'},
    {"exponent", required_argument, 0, 'd'},
    {"modulus", required_argument, 0, 'm'},
    {0, 0, 0, 0},
  };

  while (1) {
    c = getopt_long(argc, argv, "c:i:d:m:", long_options, &option_index);
    if (c < 0) {
      break;
    }
    switch(c) {
    case 0:
      usage();
      break;
    case 'c':
      c_file = fopen(optarg, "r");
      if (c_file == NULL) {
	perror("Certificate file error");
	exit(1);
      }
      break;
    case 'd':
      d_file = fopen(optarg, "r");
      if (d_file == NULL) {
	perror("Exponent file error");
	exit(1);
      }
      break;
    case 'i':
      ip_addr = inet_addr(optarg);
      break;
    case 'm':
      m_file = fopen(optarg, "r");
      if (m_file == NULL) {
	perror("Modulus file error");
	exit(1);
      }
      break;
    case '?':
      usage();
      break;
    default:
      usage();
      break;
    }
  }

  if (d_file == NULL || c_file == NULL || m_file == NULL) {
    usage();
  }
  if (argc != 9) {
    usage();
  }

  mpz_inp_str(client_exp, d_file, 0);
  mpz_inp_str(client_mod, m_file, 0);

  signal(SIGTERM, kill_handler);

  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) {
    perror("Could not open socket");
    exit(1);
  }

  memset(&server_addr, 0, sizeof(struct sockaddr_in));
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = ip_addr;
  server_addr.sin_port = htons(HANDSHAKE_PORT);
  err = connect(sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr));
  if (err < 0) {
    perror("Could not bind socket");
    cleanup();
  }

  // YOUR CODE HERE
  // IMPLEMENT THE TLS HANDSHAKE
  printf("send client hello\n");


  // send client hello
  hello_message client_hello_msg = {CLIENT_HELLO, random_int(), TLS_RSA_WITH_AES_128_ECB_SHA256};
  err = send_tls_message(sockfd, &client_hello_msg, HELLO_MSG_SIZE);
  if (err == ERR_FAILURE) {
    exit(1);
  }

  printf("receive server hello\n");

  // receive server hello
  hello_message server_hello_msg;
  err = receive_tls_message(sockfd, &server_hello_msg, HELLO_MSG_SIZE, SERVER_HELLO);
  if (err == ERR_FAILURE) {
    exit(1);
  }

  // send client certificate
  cert_message client_cert_msg;
  client_cert_msg.type = CLIENT_CERTIFICATE;
  fgets(client_cert_msg.cert, RSA_MAX_LEN, c_file);
  err = send_tls_message(sockfd, &client_cert_msg, CERT_MSG_SIZE);
  if (err == ERR_FAILURE) {
    exit(1);
  }

  printf("send client cert\n");


  //receive server certificate

  cert_message server_cert_msg;

  err = receive_tls_message(sockfd, &server_cert_msg, CERT_MSG_SIZE, SERVER_CERTIFICATE);
  if (err == ERR_FAILURE) {
    exit(1);
  }

  printf("receive server cert\n");


  mpz_t cert_plaintext;
  mpz_init(cert_plaintext);

  mpz_t ca_key_exp;
  mpz_init(ca_key_exp);

  mpz_t ca_key_mod;
  mpz_init(ca_key_mod);

  mpz_set_str(ca_key_exp, CA_EXPONENT, 0);
  mpz_set_str(ca_key_mod, CA_MODULUS, 0);

  decrypt_cert(cert_plaintext, &server_cert_msg, ca_key_exp, ca_key_mod);

  printf("decypted server cert\n");

  char cert_plaintext_string[RSA_MAX_LEN];
  mpz_get_ascii(cert_plaintext_string, cert_plaintext);


  mpz_t exponentNum;
  mpz_init(exponentNum);
  mpz_t modNum;
  mpz_init(modNum);
  get_cert_exponent(exponentNum, cert_plaintext_string);
  get_cert_modulus(modNum, cert_plaintext_string);

  // char exponentNumString[RSA_MAX_LEN];
  // char modNumString[RSA_MAX_LEN];

  // mpz_get_str(exponentNumString, 16, exponentNum);
  // mpz_get_str(modNumString, 16, modNum);

  // printf("asdf %s\n", cert_plaintext_string);


  mpz_t premaster_secret_int;
  mpz_init(premaster_secret_int);
  
  int p_secret_int = random_int();
  mpz_t p_secret;
  mpz_init(p_secret);
  mpz_add_ui(p_secret, p_secret, p_secret_int);
  printf("%x\n", premaster_secret_int);

  perform_rsa(premaster_secret_int, p_secret, exponentNum, modNum);

  ps_msg premaster_secret;
  printf("%s\n", premaster_secret.ps);
  premaster_secret.type = PREMASTER_SECRET;
  mpz_get_str(premaster_secret.ps, 16, premaster_secret_int);

  printf("%x\n", exponentNum);
  printf("%x\n", modNum);
  printf("%x\n", premaster_secret_int);
  printf("premaster secret %s\n", premaster_secret.ps);

  // send premaster secret
  err = send_tls_message(sockfd, &premaster_secret, PS_MSG_SIZE);
  if (err == ERR_FAILURE) {
    exit(1);
  }

  printf("sent premaster secret\n");
  ps_msg master_secret;

  // receive master secret
  err = receive_tls_message(sockfd, &master_secret, PS_MSG_SIZE, VERIFY_MASTER_SECRET);
  if (err == ERR_FAILURE) {
    printf("errorerrorerror\n");
    exit(1);
  }

  printf("received master secret\n");

  mpz_t decrypted_master_secret;
  mpz_init(decrypted_master_secret);

  mpz_t key_exp;
  mpz_init(key_exp);

  mpz_t key_mod;
  mpz_init(key_mod);

  
  // char *private_key_str;
  

  fseek (d_file, 0, SEEK_END);
  long length = ftell (d_file);
  fseek (d_file, 0, SEEK_SET);

  char private_key[length];
  fgets(private_key, length, d_file);
  mpz_set_str(key_exp, private_key, 0);

  fseek (m_file, 0, SEEK_END);
  length = ftell (m_file);
  fseek (m_file, 0, SEEK_SET);

  char modulus[length];
  fgets(modulus, length, m_file);
  mpz_set_str(key_mod, modulus, 0);


  decrypt_verify_master_secret(decrypted_master_secret, &master_secret, key_exp, key_mod);

  char decrypted_master_secret_char[RSA_MAX_LEN];

  mpz_get_str(decrypted_master_secret_char, 16, decrypted_master_secret);

  printf("decrypted master secret %s \n", decrypted_master_secret_char);

  unsigned char computed_master_secret[RSA_MAX_LEN];

  printf("computed before %s\n", computed_master_secret);
  compute_master_secret(p_secret_int, client_hello_msg.random, server_hello_msg.random, computed_master_secret);

  printf("computed %s\n", computed_master_secret);

  // int i = 0;
  // for (int i = 0; i < RSA_MAX_LEN; i++) {
  //   if (computed_master_secret[i] != (unsigned char)decrypted_master_secret_char[i]) {
  //     printf("error master secret");
  //     exit(1);
  //   }
  // }

  // printf("success");

  exit(1);


  /*
   * START ENCRYPTED MESSAGES
   */

  memset(send_plaintext, 0, AES_BLOCK_SIZE);
  memset(send_ciphertext, 0, AES_BLOCK_SIZE);
  memset(rcv_plaintext, 0, AES_BLOCK_SIZE);
  memset(rcv_ciphertext, 0, AES_BLOCK_SIZE);

  memset(&rcv_msg, 0, TLS_MSG_SIZE);

  aes_init(&enc_ctx);
  aes_init(&dec_ctx);
  
  // YOUR CODE HERE
  // SET AES KEYS

  fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK);
  /* Send and receive data. */
  while (1) {
    FD_ZERO(&readfds);
    FD_SET(STDIN_FILENO, &readfds);
    FD_SET(sockfd, &readfds);
    tv.tv_sec = 2;
    tv.tv_usec = 10;

    select(sockfd+1, &readfds, NULL, NULL, &tv);
    if (FD_ISSET(STDIN_FILENO, &readfds)) {
      counter = 0;
      memset(&send_msg, 0, TLS_MSG_SIZE);
      send_msg.type = ENCRYPTED_MESSAGE;
      memset(send_plaintext, 0, AES_BLOCK_SIZE);
      read_size = read(STDIN_FILENO, send_plaintext, AES_BLOCK_SIZE);
      while (read_size > 0 && counter + AES_BLOCK_SIZE < TLS_MSG_SIZE - INT_SIZE) {
	if (read_size > 0) {
	  err = aes_crypt_ecb(&enc_ctx, AES_ENCRYPT, send_plaintext, send_ciphertext);
	  memcpy(send_msg.msg + counter, send_ciphertext, AES_BLOCK_SIZE);
	  counter += AES_BLOCK_SIZE;
	}
	memset(send_plaintext, 0, AES_BLOCK_SIZE);
	read_size = read(STDIN_FILENO, send_plaintext, AES_BLOCK_SIZE);
      }
      write_size = write(sockfd, &send_msg, INT_SIZE+counter+AES_BLOCK_SIZE);
      if (write_size < 0) {
	perror("Could not write to socket");
	cleanup();
      }
    } else if (FD_ISSET(sockfd, &readfds)) {
      memset(&rcv_msg, 0, TLS_MSG_SIZE);
      memset(rcv_ciphertext, 0, AES_BLOCK_SIZE);
      read_size = read(sockfd, &rcv_msg, TLS_MSG_SIZE);
      if (read_size > 0) {
	if (rcv_msg.type != ENCRYPTED_MESSAGE) {
	  goto out;
	}
	memcpy(rcv_ciphertext, rcv_msg.msg, AES_BLOCK_SIZE);
	counter = 0;
	while (counter < read_size - INT_SIZE - AES_BLOCK_SIZE) {
	  aes_crypt_ecb(&dec_ctx, AES_DECRYPT, rcv_ciphertext, rcv_plaintext);
	  printf("%s", rcv_plaintext);
	  counter += AES_BLOCK_SIZE;
	  memcpy(rcv_ciphertext, rcv_msg.msg+counter, AES_BLOCK_SIZE);
	}
	printf("\n");
      }
    }

  }

 out:
  close(sockfd);
  return 0;
}

/*
 * \brief                  Decrypts the certificate in the message cert.
 *
 * \param decrypted_cert   This mpz_t stores the final value of the binary
 *                         for the decrypted certificate. Write the end
 *                         result here.
 * \param cert             The message containing the encrypted certificate.
 * \param key_exp          The exponent of the public key for decrypting
 *                         the certificate.
 * \param key_mod          The modulus of the public key for decrypting
 *                         the certificate.
 */

void
decrypt_cert(mpz_t decrypted_cert, cert_message *cert, mpz_t key_exp, mpz_t key_mod)
{
  mpz_t certMessage;
  mpz_init_set_str(certMessage, cert->cert, 0);
  perform_rsa(decrypted_cert, certMessage, key_exp, key_mod);

}

/*
 * \brief                  Decrypts the master secret in the message ms_ver.
 *
 * \param decrypted_ms     This mpz_t stores the final value of the binary
 *                         for the decrypted master secret. Write the end
 *                         result here.
 * \param ms_ver           The message containing the encrypted master secret.
 * \param key_exp          The exponent of the public key for decrypting
 *                         the master secret.
 * \param key_mod          The modulus of the public key for decrypting
 *                         the master secret.
 */
void
decrypt_verify_master_secret(mpz_t decrypted_ms, ps_msg *ms_ver, mpz_t key_exp, mpz_t key_mod)
{
  mpz_t masterSecret;

  printf("master secret %s\n", ms_ver->ps);
  mpz_init_set_str(masterSecret, ms_ver->ps, 16);

  perform_rsa(decrypted_ms, masterSecret, key_exp, key_mod);
}

/*
 * \brief                  Computes the master secret.
 *
 * \param ps               The premaster secret.
 * \param client_random    The random value from the client hello.
 * \param server_random    The random value from the server hello.
 * \param master_secret    A pointer to the final value of the master secret.
 *                         Write the end result here.
 */
void
compute_master_secret(int ps, int client_random, int server_random, unsigned char *master_secret)
{
  SHA256_CTX ctx;
  sha256_init(&ctx);
  int intData[4] = {ps, client_random, server_random, ps};
  unsigned char *data = (unsigned char *)intData;

  if (data[0] == data[12] && data[1] == data[13] && data[2] == data[14] && data[3] == data[15]) {
    printf("data %s", data);  
  }
  
  sha256_update(&ctx, data, 16);
  sha256_final(&ctx, master_secret);
}

/*
 * \brief                  Sends a message to the connected server.
 *                         Returns an error code.
 *
 * \param socketno         A file descriptor for the socket to send
 *                         the message on.
 * \param msg              A pointer to the message to send.
 * \param msg_len          The length of the message in bytes.
 */
int
send_tls_message(int socketno, void *msg, int msg_len)
{
  int err = write(socketno, msg, msg_len);

  if (err == -1) {
    return ERR_FAILURE;
  }
  
  return ERR_OK;
}

/*
 * \brief                  Receieves a message from the connected server.
 *                         Returns an error code.
 *
 * \param socketno         A file descriptor for the socket to receive
 *                         the message on.
 * \param msg              A pointer to where to store the received message.
 * \param msg_len          The length of the message in bytes.
 * \param msg_type         The expected type of the message to receive.
 */
int
receive_tls_message(int socketno, void *msg, int msg_len, int msg_type)
{
  int err = read(socketno, msg, msg_len);
  int type = *((int *)msg);
  if (type == msg_type) {
    return ERR_OK;
  } else {
    return ERR_FAILURE;
  }
}


/*
 * \brief                Encrypts/decrypts a message using the RSA algorithm.
 *
 * \param result         a field to populate with the result of your RSA calculation.
 * \param message        the message to perform RSA on. (probably a cert in this case)
 * \param e              the encryption key from the key_file passed in through the
 *                       command-line arguments
 * \param n              the modulus for RSA from the modulus_file passed in through
 *                       the command-line arguments
 *
 * Fill in this function with your proj0 solution or see staff solutions.
 */
static void
perform_rsa(mpz_t result, mpz_t message, mpz_t e, mpz_t n)
{
  mpz_t odd;
  mpz_init(odd);
  mpz_add_ui(result, result, 1);

  while (mpz_cmp_ui(e, 0)){
      mpz_mod_ui(odd, e, 2);
      if (mpz_cmp_ui(odd, 0)) {
          mpz_mul(result, result, message);
          mpz_mod(result, result, n);
          mpz_sub_ui(e, e, 1);
      } else {
          mpz_mul(message, message, message);
          mpz_mod(message, message, n);
          mpz_div_ui(e, e, 2);
      }
    } 

    mpz_clear(odd);
}


/* Returns a pseudo-random integer. */
static int
random_int()
{
  srand(time(NULL));
  return rand();
}

/*
 * \brief                 Returns ascii string from a number in mpz_t form.
 *
 * \param output_str      A pointer to the output string.
 * \param input           The number to convert to ascii.
 */
void
mpz_get_ascii(char *output_str, mpz_t input)
{
  int i,j;
  char *result_str;
  result_str = mpz_get_str(NULL, HEX_BASE, input);
  i = 0;
  j = 0;
  while (result_str[i] != '\0') {
    output_str[j] = hex_to_ascii(result_str[i], result_str[i+1]);
    j += 1;
    i += 2;
  }
}

/*
 * \brief                  Returns a pointer to a string containing the
 *                         characters representing the input hex value.
 *
 * \param data             The input hex value.
 * \param data_len         The length of the data in bytes.
 */
char
*hex_to_str(char *data, int data_len)
{
  int i;
  char *output_str = calloc(1+2*data_len, sizeof(char));
  for (i = 0; i < data_len; i += 1) {
    snprintf(output_str+2*i, 3, "%02X", (unsigned int) (data[i] & 0xFF));
  }
  return output_str;
}

/* Return the public key exponent given the decrypted certificate as string. */
int
get_cert_exponent(mpz_t result, char *cert)
{
  int err;
  char *srch, *srch2;
  char exponent[RSA_MAX_LEN/2];
  memset(exponent, 0, RSA_MAX_LEN/2);
  srch = strchr(cert, '\n');
  if (srch == NULL) {
    return ERR_FAILURE;
  }
  srch += 1;
  srch = strchr(srch, '\n');
  if (srch == NULL) {
    return ERR_FAILURE;
  }
  srch += 1;
  srch = strchr(srch, '\n');
  if (srch == NULL) {
    return ERR_FAILURE;
  }
  srch += 1;
  srch = strchr(srch, ':');
  if (srch == NULL) {
    return ERR_FAILURE;
  }
  srch += 2;
  srch2 = strchr(srch, '\n');
  if (srch2 == NULL) {
    return ERR_FAILURE;
  }
  strncpy(exponent, srch, srch2-srch);
  err = mpz_set_str(result, exponent, 0);
  if (err == -1) {
    return ERR_FAILURE;
  }
  return ERR_OK;
}

/* Return the public key modulus given the decrypted certificate as string. */
int
get_cert_modulus(mpz_t result, char *cert)
{
  int err;
  char *srch, *srch2;
  char modulus[RSA_MAX_LEN/2];
  memset(modulus, 0, RSA_MAX_LEN/2);
  srch = strchr(cert, '\n');
  if (srch == NULL) {
    return ERR_FAILURE;
  }
  srch += 1;
  srch = strchr(srch, '\n');
  if (srch == NULL) {
    return ERR_FAILURE;
  }
  srch += 1;
  srch = strchr(srch, ':');
  if (srch == NULL) {
    return ERR_FAILURE;
  }
  srch += 2;
  srch2 = strchr(srch, '\n');
  if (srch2 == NULL) {
    return ERR_FAILURE;
  }
  strncpy(modulus, srch, srch2-srch);
  err = mpz_set_str(result, modulus, 0);
  if (err == -1) {
    return ERR_FAILURE;
  }
  return ERR_OK;
}

/* Prints the usage string for this program and exits. */
static void
usage()
{
    printf("./client -i <server_ip_address> -c <certificate_file> -m <modulus_file> -d <exponent_file>\n");
    exit(1);
}

/* Catches the signal from C-c and closes connection with server. */
static void
kill_handler(int signum)
{
  if (signum == SIGTERM) {
    cleanup();
  }
}

/* Converts the two input hex characters into an ascii char. */
static int
hex_to_ascii(char a, char b)
{
    int high = hex_to_int(a) * 16;
    int low = hex_to_int(b);
    return high + low;
}

/* Converts a hex value into an int. */
static int
hex_to_int(char a)
{
    if (a >= 97) {
	a -= 32;
    }
    int first = a / 16 - 3;
    int second = a % 16;
    int result = first*10 + second;
    if (result > 9) {
	result -= 1;
    }
    return result;
}

/* Closes files and exits the program. */
static void
cleanup()
{
  close(sockfd);
  exit(1);
}
