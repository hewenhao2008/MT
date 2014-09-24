#include "common.h"

static char s_passwd_fname[PATH_MAX];

int ev_auth_handler(struct mg_connection *conn, enum mg_event ev) {

  if (ev == MG_AUTH) {
    int result = MG_FALSE; // Not authorized
    FILE *fp;

    // To populate passwords file, do
    // mongoose -A my_passwords.txt mydomain.com admin admin
    abs_path("passwd", s_passwd_fname, sizeof(s_passwd_fname));
    if ((fp = fopen(s_passwd_fname, "r")) != NULL) {
      result = mg_authorize_digest(conn, fp);
      fclose(fp);
      //fprintf(stderr, "%s: auth result: %d\n", __FUNCTION__, result);
    }else{
      fprintf(stderr, "%s: open passwd[%s] file failed.\n", __FUNCTION__, s_passwd_fname);
    }


    return result;
  }

  return MG_FALSE;
}

// int main(void) {
//   struct mg_server *server = mg_create_server(NULL, ev_handler);
//   mg_set_option(server, "listening_port", "8080");
//   mg_set_option(server, "document_root", ".");

//   printf("Starting on port %s\n", mg_get_option(server, "listening_port"));
//   for (;;) {
//     mg_poll_server(server, 1000);
//   }
//   mg_destroy_server(&server);

//   return 0;
// }
