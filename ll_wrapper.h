#define LL_WRAPPER

extern int landlock_create_ruleset(struct landlock_ruleset_attr *rsattr,size_t size,__u32 flags);

extern int landlock_add_rule(int fd,enum landlock_rule_type t,void *attr,__u32 flags);

extern int landlock_restrict_self(int fd,__u32 flags);
