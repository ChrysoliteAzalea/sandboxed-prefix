#define LIBADDRULE

extern int add_read_access_rule(int rset_fd,int allowed_fd);

extern int add_write_access_rule(int rset_fd,int allowed_fd,int restricted);

extern int add_execute_rule(int rset_fd,int allowed_fd);
