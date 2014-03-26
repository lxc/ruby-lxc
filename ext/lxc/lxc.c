#include <ruby.h>
#include <linux/personality.h> /* for PER_* constants */
#include <linux/sched.h>       /* for CLONE_* constants */
#include <lxc/lxccontainer.h>
#include <lxc/attach_options.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>

#define SYMBOL(s) ID2SYM(rb_intern(s))

#if defined(HAVE_RB_THREAD_CALL_WITHOUT_GVL)
// Defined in Ruby, but not in all Ruby versions' header files
extern void *rb_thread_call_without_gvl(void *(*func)(void *), void *data1,
				                                rb_unblock_function_t *ubf, void *data2);
#define WITHOUT_GVL_RESULT_TYPE void *
#define WITHOUT_GVL_RESULT(__X__) (void *)(intptr_t)(__X__)
#define WITHOUT_GVL_CALL(__FUNC__, __ARG__) (int)(intptr_t)rb_thread_call_without_gvl(__FUNC__, __ARG__, NULL, NULL)
#define WITHOUT_GVL_CALL_NOOP(__FUNC__, __ARG__) rb_thread_call_without_gvl(__FUNC__, __ARG__, NULL, NULL)
#define WITHOUT_GVL_CALL2(__FUNC__, __ARG__, __KILLFUNC__, __KILLARG__) (int)(intptr_t)rb_thread_call_without_gvl(__FUNC__, __ARG__, __KILLFUNC__, __KILLARG__)
#elif defined(HAVE_RB_THREAD_BLOCKING_REGION)
#define WITHOUT_GVL_RESULT_TYPE VALUE
#define WITHOUT_GVL_RESULT(__X__) INT2NUM(__X__)
#define WITHOUT_GVL_CALL(__FUNC__, __ARG__) NUM2INT(rb_thread_blocking_region(__FUNC__, __ARG__, NULL, NULL))
#define WITHOUT_GVL_CALL_NOOP(__FUNC__, __ARG__) rb_thread_blocking_region(__FUNC__, __ARG__, NULL, NULL)
#define WITHOUT_GVL_CALL2(__FUNC__, __ARG__, __KILLFUNC__, __KILLARG__) NUM2INT(rb_thread_blocking_region(__FUNC__, __ARG__, __KILLFUNC__, __KILLARG__))
#else
#define WITHOUT_GVL_RESULT_TYPE int
#define WITHOUT_GVL_RESULT(__X__) __X__
#define WITHOUT_GVL_CALL(__FUNC__, __ARG__) __FUNC__(__ARG__)
#define WITHOUT_GVL_CALL_NOOP(__FUNC__, __ARG__) __FUNC__(__ARG__)
#define WITHOUT_GVL_CALL2(__FUNC__, __ARG__, __KILLFUNC__, __KILLARG__) __FUNC__(__ARG__)
#endif

extern int lxc_wait_for_pid_status(pid_t pid);
extern long lxc_config_parse_arch(const char *arch);

static VALUE Container;
static VALUE Error;

struct container_data {
    struct lxc_container *container;
};

static char **
ruby_to_c_string_array(VALUE rb_arr)
{
    size_t i, len;
    char **arr;

    len = RARRAY_LEN(rb_arr);
    arr = calloc(len + 1, sizeof(char *));
    if (arr == NULL)
        rb_raise(rb_eNoMemError, "unable to allocate array");
    for (i = 0; i < len; i++) {
        VALUE s = rb_ary_entry(rb_arr, i);
        arr[i] = strdup(StringValuePtr(s));
    }
    arr[len] = NULL;

    return arr;
}

static void
free_c_string_array(char **arr)
{
    size_t i;
    for (i = 0; arr[i] != NULL; i++)
        free(arr[i]);
    free(arr);
}

/*
 * Document-module: LXC
 *
 * This module provides a Ruby API allowing programmatic managing of
 * "Linux Containers"[http://linuxcontainers.org/].
 *
 * The +LXC+ module contains generic methods (which are not related to
 * a specific container instance) and methods related to +liblxc+. The
 * container-specific methods are contained in the +LXC::Container+ class.
 */

/*
 * call-seq:
 *   LXC.arch_to_personality(arch)
 *
 * Converts an architecture string (x86, i686, x86_64 or amd64) to a
 * "personality", either +:linux32+ or +:linux+, for the 32-bit and 64-bit
 * architectures, respectively.
 */
static VALUE
lxc_arch_to_personality(VALUE self, VALUE rb_arch)
{
    int ret;
    char *arch;

    arch = StringValuePtr(rb_arch);
    ret = lxc_config_parse_arch(arch);

    switch (ret) {
    case PER_LINUX32:
        return SYMBOL("linux32");
    case PER_LINUX:
        return SYMBOL("linux");
    default:
        rb_raise(Error, "unknown personality");
    }
}

/*
 * call-seq:
 *   LXC.run_command(command)
 *
 * Runs the given command (given as a string or as an argv array) in
 * an attached container. Useful in conjunction with +LXC::Container#attach+.
 */
static VALUE
lxc_run_command(VALUE self, VALUE rb_command)
{
    int ret;
    lxc_attach_command_t cmd;
    VALUE rb_program;

    if (TYPE(rb_command) == T_STRING)
        rb_command = rb_str_split(rb_command, " ");

    rb_program = rb_ary_entry(rb_command, 0);
    cmd.program = StringValuePtr(rb_program);
    cmd.argv = ruby_to_c_string_array(rb_command);

    ret = lxc_attach_run_command(&cmd);
    if (ret == -1)
        rb_raise(Error, "unable to run command on attached container");
    /* NOTREACHED */
    return Qnil;
}

/*
 * call-seq:
 *   LXC.run_shell
 *
 * Runs a shell in an attached container. Useful in conjunction with
 * +LXC::Container#attach+.
 */
static VALUE
lxc_run_shell(VALUE self)
{
    int ret;

    ret = lxc_attach_run_shell(NULL);
    if (ret == -1)
        rb_raise(Error, "unable to run shell on attached container");
    /* NOTREACHED */
    return Qnil;
}

/*
 * call-seq:
 *   LXC.global_config_item(key)
 *
 * Returns value for the given global config key.
 */
static VALUE
lxc_global_config_item(VALUE self, VALUE rb_key)
{
    char *key;
    const char *value;
    key = StringValuePtr(rb_key);
    value = lxc_get_global_config_item(key);
    if (value == NULL)
        rb_raise(Error, "invalid configuration key %s", key);
    return rb_str_new2(value);
}

/*
 * call-seq:
 *   LXC.version
 *
 * Returns the +liblxc+ version.
 */
static VALUE
lxc_version(VALUE self)
{
    return rb_str_new2(lxc_get_version());
}

struct list_containers_without_gvl_args
{
    int active;
    int defined;
    char *config;
    char **names;
};

static WITHOUT_GVL_RESULT_TYPE
list_containers_without_gvl(void *args_void)
{
    struct list_containers_without_gvl_args *args = (struct list_containers_without_gvl_args *)args_void;
    int num_containers = 0;
    args->names = NULL;
    if (args->active && args->defined)
        num_containers = list_all_containers(args->config, &args->names, NULL);
    else if (args->active)
        num_containers = list_active_containers(args->config, &args->names, NULL);
    else if (args->defined)
        num_containers = list_defined_containers(args->config, &args->names, NULL);
    return WITHOUT_GVL_RESULT(num_containers);
}

/*
 * call-seq:
 *   LXC.list_containers([opts])
 *
 * Returns an array of containers. Which containers are returned depends on
 * the options hash: by default, all containers are returned. One may list
 * only active or defined containers by setting either the +:active+ or
 * +:defined+ keys to +true+. The +:config_path+ key allows an alternate
 * configuration path to be scanned when building the list.
 */
static VALUE
lxc_list_containers(int argc, VALUE *argv, VALUE self)
{
    int i, num_containers;
    VALUE rb_active, rb_defined, rb_config;
    VALUE rb_opts;
    VALUE rb_containers;
    struct list_containers_without_gvl_args args;

    rb_scan_args(argc, argv, "01", &rb_opts);

    args.active = 1;
    args.defined = 1;
    args.config = NULL;

    if (!NIL_P(rb_opts)) {
        Check_Type(rb_opts, T_HASH);

        rb_active = rb_hash_aref(rb_opts, SYMBOL("active"));
        if (!NIL_P(rb_active))
            args.active = rb_active != Qfalse;

        rb_defined = rb_hash_aref(rb_opts, SYMBOL("defined"));
        if (!NIL_P(rb_defined))
            args.defined = rb_defined != Qfalse;

        rb_config = rb_hash_aref(rb_opts, SYMBOL("config_path"));
        if (!NIL_P(rb_config))
            args.config = StringValuePtr(rb_config);
    }
    num_containers = WITHOUT_GVL_CALL(list_containers_without_gvl, &args);
    if (num_containers < 0)
        rb_raise(Error, "failure to list containers");

    rb_containers = rb_ary_new2(num_containers);
    /*
     * The `names` array is not NULL-terminated, so free it manually,
     * ie, don't use free_c_string_array().
     */
    for (i = 0; i < num_containers; i++) {
        rb_ary_store(rb_containers, i, rb_str_new2(args.names[i]));
        free(args.names[i]);
    }
    free(args.names);

    return rb_containers;
}


/*
 * Document-class: LXC::Container
 *
 * This class contains methods to manage Linux containers.
 */

static void
container_free(void *data)
{
    struct container_data *d = (struct container_data *)data;
    lxc_container_put(d->container);
    free(d);
}

static VALUE
container_alloc(VALUE klass)
{
    struct container_data *data;
    return Data_Make_Struct(klass, struct container_data, NULL,
                            container_free, data);
}

/*
 * call-seq:
 *   LXC::Container.new(name, config_path = LXC.global_config_item('lxc.lxcpath'))
 *
 * Creates a new container instance with the given name, under the given
 * configuration path.
 */
static VALUE
container_initialize(int argc, VALUE *argv, VALUE self)
{
    char *name, *config_path;
    struct lxc_container *container;
    struct container_data *data;
    VALUE rb_name, rb_config_path;

    rb_scan_args(argc, argv, "11", &rb_name, &rb_config_path);

    name = StringValuePtr(rb_name);
    config_path = NIL_P(rb_config_path) ? NULL : StringValuePtr(rb_config_path);

    container = lxc_container_new(name, config_path);
    if (container == NULL)
        rb_raise(Error, "error creating container %s", name);

    Data_Get_Struct(self, struct container_data, data);
    data->container = container;

    return self;
}

/*
 * call-seq:
 *   container.config_file_name
 *
 * Returns the name of the container's configuration file.
 */
static VALUE
container_config_file_name(VALUE self)
{
    char *config_file_name;
    struct container_data *data;

    Data_Get_Struct(self, struct container_data, data);
    config_file_name = data->container->config_file_name(data->container);

    return rb_str_new2(config_file_name);
}

static VALUE
container_controllable_p(VALUE self)
{
    int controllable;
    struct container_data *data;

    Data_Get_Struct(self, struct container_data, data);
    controllable = data->container->may_control(data->container);

    return controllable ? Qtrue : Qfalse;
}

static VALUE
container_defined_p(VALUE self)
{
    int defined;
    struct container_data *data;

    Data_Get_Struct(self, struct container_data, data);
    defined = data->container->is_defined(data->container);

    return defined ? Qtrue : Qfalse;
}

/*
 * call-seq:
 *   container.init_pid
 *
 * Returns the PID of the container's +init+ process from the host's
 * point of view.
 */
static VALUE
container_init_pid(VALUE self)
{
    pid_t pid;
    struct container_data *data;

    Data_Get_Struct(self, struct container_data, data);
    pid = data->container->init_pid(data->container);
    if (pid < 0)
        return Qnil;
    return INT2NUM(pid);
}

/*
 * call-seq:
 *   container.name
 *
 * Returns the name of the container.
 */
static VALUE
container_name(VALUE self)
{
    struct container_data *data;

    Data_Get_Struct(self, struct container_data, data);

    return rb_str_new2(data->container->name);
}

static VALUE
container_running_p(VALUE self)
{
    int running;
    struct container_data *data;

    Data_Get_Struct(self, struct container_data, data);
    running = data->container->is_running(data->container);

    return running ? Qtrue : Qfalse;
}

/*
 * call-seq:
 *   container.state
 *
 * Returns a symbol representing the state of the container.
 */
static VALUE
container_state(VALUE self)
{
    struct container_data *data;
    VALUE rb_state;

    Data_Get_Struct(self, struct container_data, data);
    rb_state = rb_str_new2(data->container->state(data->container));

    return rb_str_intern(rb_funcall(rb_state, rb_intern("downcase"), 0));
}

struct add_device_node_without_gvl_args
{
    struct container_data *data;
    char *src_path;
    char *dest_path;
};

static WITHOUT_GVL_RESULT_TYPE
add_device_node_without_gvl(void *args_void)
{
    struct add_device_node_without_gvl_args *args = (struct add_device_node_without_gvl_args *)args_void;
    return WITHOUT_GVL_RESULT(args->data->container->add_device_node(args->data->container, args->src_path, args->dest_path));
}

/*
 * call-seq:
 *   container.add_device_node(src_path, dest_path = src_path)
 *
 * Adds a device node to the container.
 */
static VALUE
container_add_device_node(int argc, VALUE *argv, VALUE self)
{
    int ret;
    VALUE rb_src_path, rb_dest_path;
    struct add_device_node_without_gvl_args args;

    rb_scan_args(argc, argv, "11", &rb_src_path, &rb_dest_path);
    args.src_path = StringValuePtr(rb_src_path);
    args.dest_path = NIL_P(rb_dest_path) ? NULL : StringValuePtr(rb_dest_path);

    Data_Get_Struct(self, struct container_data, args.data);

    ret = WITHOUT_GVL_CALL(add_device_node_without_gvl, &args);
    if (!ret)
        rb_raise(Error, "unable to add device node");

    return self;
}

static VALUE
lxc_attach_exec_block_cb(VALUE block)
{
    rb_funcall3(block, rb_intern("call"), 0, NULL);
    return INT2FIX(0);
}

static VALUE
lxc_attach_exec_rescue_cb()
{
    return INT2FIX(1);
}

static int
lxc_attach_exec(void *payload)
{
    VALUE res = rb_rescue(lxc_attach_exec_block_cb, (VALUE)payload,
                          lxc_attach_exec_rescue_cb, (VALUE)NULL);
    return FIX2INT(res);
}

static int
io_fileno(VALUE io)
{
    return NUM2INT(rb_funcall(io, rb_intern("fileno"), 0));
}

static int
is_integer(VALUE v)
{
    return (TYPE(v) == T_FIXNUM || TYPE(v) == T_BIGNUM);
}

static int
is_string(VALUE v)
{
    return TYPE(v) == T_STRING;
}

static int
is_string_array(VALUE v)
{
    size_t i, len;
    if (TYPE(v) != T_ARRAY)
        return 0;
    len = RARRAY_LEN(v);
    for (i = 0; i < len; i++) {
        if (TYPE(rb_ary_entry(v, i)) != T_STRING)
            return 0;
    }
    return 1;
}

static int
is_io(VALUE v)
{
    return rb_respond_to(v, rb_intern("sysread")) &&
           rb_respond_to(v, rb_intern("syswrite"));
}

static void
lxc_attach_free_options(lxc_attach_options_t *opts)
{
    if (!opts)
        return;
    if (opts->initial_cwd)
        free(opts->initial_cwd);
    if (opts->extra_env_vars)
        free_c_string_array(opts->extra_env_vars);
    if (opts->extra_keep_env)
        free_c_string_array(opts->extra_keep_env);
    free(opts);
}

static lxc_attach_options_t *
lxc_attach_parse_options(VALUE rb_opts)
{
    lxc_attach_options_t default_opts = LXC_ATTACH_OPTIONS_DEFAULT;
    lxc_attach_options_t *opts;
    VALUE rb_attach_flags, rb_namespaces, rb_personality, rb_initial_cwd;
    VALUE rb_uid, rb_gid, rb_env_policy, rb_extra_env_vars, rb_extra_keep_env;
    VALUE rb_stdin, rb_stdout, rb_stderr;

    opts = malloc(sizeof(*opts));
    if (opts == NULL)
        rb_raise(rb_eNoMemError, "unable to allocate options");
    memcpy(opts, &default_opts, sizeof(*opts));

    if (NIL_P(rb_opts))
        return opts;

    rb_attach_flags = rb_hash_aref(rb_opts, SYMBOL("flags"));
    if (!NIL_P(rb_attach_flags)) {
        if (is_integer(rb_attach_flags))
            opts->attach_flags = NUM2INT(rb_attach_flags);
        else
            goto err;
    }
    rb_namespaces = rb_hash_aref(rb_opts, SYMBOL("namespaces"));
    if (!NIL_P(rb_namespaces)) {
        if (is_integer(rb_namespaces))
            opts->namespaces = NUM2INT(rb_namespaces);
        else
            goto err;
    }
    rb_personality = rb_hash_aref(rb_opts, SYMBOL("personality"));
    if (!NIL_P(rb_personality)) {
        if (is_integer(rb_personality))
            opts->personality = NUM2INT(rb_personality);
        else
            goto err;
    }
    rb_initial_cwd = rb_hash_aref(rb_opts, SYMBOL("initial_cwd"));
    if (!NIL_P(rb_initial_cwd)) {
        if (is_string(rb_initial_cwd))
            opts->initial_cwd = StringValuePtr(rb_initial_cwd);
        else
            goto err;
    }
    rb_uid = rb_hash_aref(rb_opts, SYMBOL("uid"));
    if (!NIL_P(rb_uid)) {
        if (is_integer(rb_uid))
            opts->uid = NUM2INT(rb_uid);
        else
            goto err;
    }
    rb_gid = rb_hash_aref(rb_opts, SYMBOL("gid"));
    if (!NIL_P(rb_gid)) {
        if (is_integer(rb_gid))
            opts->gid = NUM2INT(rb_gid);
        else
            goto err;
    }
    rb_env_policy = rb_hash_aref(rb_opts, SYMBOL("env_policy"));
    if (!NIL_P(rb_env_policy)) {
        if (is_integer(rb_env_policy))
            opts->env_policy = NUM2INT(rb_env_policy);
        else
            goto err;
    }
    rb_extra_env_vars = rb_hash_aref(rb_opts, SYMBOL("extra_env_vars"));
    if (!NIL_P(rb_extra_env_vars)) {
        if (is_string_array(rb_extra_env_vars))
            opts->extra_env_vars = ruby_to_c_string_array(rb_extra_env_vars);
        else
            goto err;
    }
    rb_extra_keep_env = rb_hash_aref(rb_opts, SYMBOL("extra_keep_env"));
    if (!NIL_P(rb_extra_keep_env)) {
        if (is_string_array(rb_extra_keep_env))
            opts->extra_keep_env = ruby_to_c_string_array(rb_extra_keep_env);
        else
            goto err;
    }
    rb_stdin = rb_hash_aref(rb_opts, SYMBOL("stdin"));
    if (!NIL_P(rb_stdin)) {
        if (is_io(rb_stdin))
            opts->stdin_fd = io_fileno(rb_stdin);
        else
            goto err;
    }
    rb_stdout = rb_hash_aref(rb_opts, SYMBOL("stdout"));
    if (!NIL_P(rb_stdout)) {
        if (is_io(rb_stdout))
            opts->stdout_fd = io_fileno(rb_stdout);
        else
            goto err;
    }
    rb_stderr = rb_hash_aref(rb_opts, SYMBOL("stderr"));
    if (!NIL_P(rb_stderr)) {
        if (is_io(rb_stderr))
            opts->stderr_fd = io_fileno(rb_stderr);
        else
            goto err;
    }

    return opts;

err:
    lxc_attach_free_options(opts);
    return NULL;
}

static WITHOUT_GVL_RESULT_TYPE
lxc_wait_for_pid_status_without_gvl(void *pid)
{
  return WITHOUT_GVL_RESULT(lxc_wait_for_pid_status(*(pid_t*)pid));
}

#if defined(HAVE_RB_THREAD_CALL_WITHOUT_GVL) || defined(HAVE_RB_THREAD_BLOCKING_REGION)
static void
kill_pid_without_gvl(void *pid)
{
  kill(*(pid_t *)pid, SIGKILL);
}
#endif

/*
 * call-seq:
 *   container.attach(opts = {}, &block)
 *
 * Calls +block+ in the context of the attached container. The options may
 * contain the following keys.
 *
 * * +:flags+
 * * +:namespaces+
 * * +:personality+
 * * +:initial_cwd+
 * * +:uid+
 * * +:gid+
 * * +:env_policy+
 * * +:extra_env_vars+
 * * +:extra_keep_env+
 * * +:stdin+
 * * +:stdout+
 * * +:stderr+
 * * +:wait+
 */
static VALUE
container_attach(int argc, VALUE *argv, VALUE self)
{
    int wait;
    long ret;
    pid_t pid;
    lxc_attach_options_t *opts;
    struct container_data *data;
    VALUE block, rb_opts;

    if (!rb_block_given_p())
        rb_raise(Error, "no block given");
    block = rb_block_proc();

    rb_scan_args(argc, argv, "01", &rb_opts);

    wait = 0;
    if (!NIL_P(rb_opts)) {
        VALUE rb_wait;
        Check_Type(rb_opts, T_HASH);
        rb_wait = rb_hash_delete(rb_opts, SYMBOL("wait"));
        if (rb_wait != Qnil && rb_wait != Qfalse)
            wait = 1;
    }
    opts = lxc_attach_parse_options(rb_opts);
    if (opts == NULL)
        rb_raise(Error, "unable to parse attach options");

    Data_Get_Struct(self, struct container_data, data);

    ret = data->container->attach(data->container, lxc_attach_exec,
                                  (void *)block, opts, &pid);
    if (ret < 0)
        goto out;

    if (wait) {
        ret = WITHOUT_GVL_CALL2(lxc_wait_for_pid_status_without_gvl, &pid,
                                kill_pid_without_gvl, &pid);
        /* handle case where attach fails */
        if (WIFEXITED(ret) && WEXITSTATUS(ret) == 255)
            ret = -1;
    } else {
        ret = pid;
    }

out:
    lxc_attach_free_options(opts);
    return LONG2NUM(ret);
}

/*
 * call-seq:
 *   container.clear_config
 *
 * Clears the container configuration.
 */
static VALUE
container_clear_config(VALUE self)
{
    struct container_data *data;
    Data_Get_Struct(self, struct container_data, data);
    data->container->clear_config(data->container);
    return self;
}

/*
 * call-seq:
 *   container.clear_config_item(key)
 *
 * Clears the container configuration item +key+.
 */
static VALUE
container_clear_config_item(VALUE self, VALUE rb_key)
{
    int ret;
    char *key;
    struct container_data *data;

    key = StringValuePtr(rb_key);

    Data_Get_Struct(self, struct container_data, data);

    ret = data->container->clear_config_item(data->container, key);
    if (!ret)
        rb_raise(Error, "unable to clear config item %s", key);

    return self;
}

struct clone_without_gvl_args
{
    struct container_data *data;
    struct lxc_container *new_container;
    char *name;
    char *config_path;
    int flags;
    char *bdev_type;
    char *bdev_data;
    uint64_t new_size;
    char **hook_args;
};

static WITHOUT_GVL_RESULT_TYPE
clone_without_gvl(void *args_void)
{
    struct clone_without_gvl_args *args = (struct clone_without_gvl_args *)args_void;
    struct lxc_container *container = args->data->container;
    args->new_container = container->clone(container, args->name,
        args->config_path, args->flags, args->bdev_type, args->bdev_data,
        args->new_size, args->hook_args);
    return WITHOUT_GVL_RESULT(0);
}

/*
 * call-seq:
 *   container.clone(clone_name, opts = {})
 *
 * Clones the container, returning a new one with the given name. The
 * options hash may contain the following keys:
 *
 * * +:config_path+
 * * +:flags+
 * * +:bdev_type+
 * * +:bdev_data+
 * * +:new_size+
 * * +:hook_args+
 */
static VALUE
container_clone(int argc, VALUE *argv, VALUE self)
{
    VALUE rb_name, rb_opts;
    VALUE rb_flags, rb_config_path, rb_bdev_type, rb_bdev_data;
    VALUE rb_new_size, rb_hook_args;
    VALUE rb_args[2];
    struct clone_without_gvl_args args;

    rb_scan_args(argc, argv, "11", &rb_name, &rb_opts);

    args.name = StringValuePtr(rb_name);

    args.config_path = NULL;
    args.flags       = 0;
    args.bdev_type   = NULL;
    args.bdev_data   = NULL;
    args.new_size    = 0;
    args.hook_args   = NULL;

    rb_config_path = Qnil;

    if (!NIL_P(rb_opts)) {
        Check_Type(rb_opts, T_HASH);
        rb_config_path = rb_hash_aref(rb_opts, SYMBOL("config_path"));
        if (!NIL_P(rb_config_path))
            args.config_path = StringValuePtr(rb_config_path);

        rb_flags = rb_hash_aref(rb_opts, SYMBOL("flags"));
        if (!NIL_P(rb_flags))
            args.flags = NUM2INT(rb_flags);

        rb_bdev_type = rb_hash_aref(rb_opts, SYMBOL("bdev_type"));
        if (!NIL_P(rb_bdev_type))
            args.bdev_type = StringValuePtr(rb_bdev_type);

        rb_bdev_data = rb_hash_aref(rb_opts, SYMBOL("bdev_data"));
        if (!NIL_P(rb_bdev_data))
            args.bdev_data = StringValuePtr(rb_bdev_data);

        rb_new_size = rb_hash_aref(rb_opts, SYMBOL("new_size"));
        if (!NIL_P(rb_bdev_data))
            args.new_size = NUM2ULL(rb_new_size);

        rb_hook_args = rb_hash_aref(rb_opts, SYMBOL("hook_args"));
        if (!NIL_P(rb_hook_args))
            args.hook_args = ruby_to_c_string_array(rb_hook_args);
    }

    Data_Get_Struct(self, struct container_data, args.data);

    WITHOUT_GVL_CALL_NOOP(clone_without_gvl, &args);

    if (args.hook_args)
        free_c_string_array(args.hook_args);

    if (args.new_container == NULL)
        rb_raise(Error, "unable to clone container");

    lxc_container_put(args.new_container);

    rb_args[0] = rb_name;
    rb_args[1] = rb_config_path;
    return rb_class_new_instance(2, rb_args, Container);
}

struct console_without_gvl_args
{
    struct container_data *data;
    int tty_num;
    int stdin_fd;
    int stdout_fd;
    int stderr_fd;
    int escape;
};

static WITHOUT_GVL_RESULT_TYPE
console_without_gvl(void *args_void)
{
    struct console_without_gvl_args *args = (struct console_without_gvl_args *)args_void;
    struct lxc_container *container = args->data->container;
    return WITHOUT_GVL_RESULT(container->console(container, args->tty_num,
                                                 args->stdin_fd, args->stdout_fd,
                                                 args->stderr_fd, args->escape));
}

/*
 * call-seq:
 *   container.console(opts = {})
 *
 * Accesses the container's console. The options hash may contain the
 * following keys.
 *
 * * +:tty_num+
 * * +:stdin_fd+
 * * +:stdout_fd+
 * * +:stderr_fd+
 * * +:escape+
 */
static VALUE
container_console(int argc, VALUE *argv, VALUE self)
{
    int ret;
    struct console_without_gvl_args args;
    VALUE rb_opts;
    VALUE rb_opt;

    args.tty_num = -1;
    args.stdin_fd = 0;
    args.stdout_fd = 1;
    args.stderr_fd = 2;
    args.escape = 1;

    rb_scan_args(argc, argv, "01", &rb_opts);
    switch (TYPE(rb_opts)) {
    case T_HASH:
        rb_opt = rb_hash_aref(rb_opts, SYMBOL("tty_num"));
        if (!NIL_P(rb_opt))
          args.tty_num = NUM2INT(rb_opt);
        rb_opt = rb_hash_aref(rb_opts, SYMBOL("stdin_fd"));
        if (!NIL_P(rb_opt))
          args.stdin_fd = NUM2INT(rb_opt);
        rb_opt = rb_hash_aref(rb_opts, SYMBOL("stdout_fd"));
        if (!NIL_P(rb_opt))
          args.stdout_fd = NUM2INT(rb_opt);
        rb_opt = rb_hash_aref(rb_opts, SYMBOL("stderr_fd"));
        if (!NIL_P(rb_opt))
          args.stderr_fd = NUM2INT(rb_opt);
        rb_opt = rb_hash_aref(rb_opts, SYMBOL("escape"));
        if (!NIL_P(rb_opt))
          args.escape = NUM2INT(rb_opt);
        break;
    case T_NIL:
        break;
    default:
        rb_raise(rb_eArgError, "options must be a hash");
    }

    Data_Get_Struct(self, struct container_data, args.data);

    ret = WITHOUT_GVL_CALL(console_without_gvl, &args);
    if (ret != 0)
        rb_raise(Error, "unable to access container console");

    return self;
}

/*
 * call-seq:
 *   container.console_fd(tty_num = nil)
 *
 * Returns an IO object referring to the container's console file descriptor.
 */
static VALUE
container_console_fd(int argc, VALUE *argv, VALUE self)
{
    int ret, tty_num, master_fd;
    struct container_data *data;
    VALUE rb_tty_num;
    VALUE rb_io_args[1];

    rb_scan_args(argc, argv, "01", &rb_tty_num);
    tty_num = NIL_P(rb_tty_num) ? -1 : NUM2INT(rb_tty_num);

    Data_Get_Struct(self, struct container_data, data);

    ret = data->container->console_getfd(data->container, &tty_num, &master_fd);
    if (ret < 0)
        rb_raise(Error, "unable to allocate tty");

    rb_io_args[0] = INT2NUM(master_fd);
    return rb_class_new_instance(1, rb_io_args, rb_cIO);
}

/* Used to run container->create outside of GIL */
struct container_create_without_gvl_args {
    struct container_data *data;
    char *template;
    char *bdevtype;
    int flags;
    char **args;
};

static WITHOUT_GVL_RESULT_TYPE
container_create_without_gvl(void *args_void)
{
    struct container_create_without_gvl_args *args = (struct container_create_without_gvl_args *)args_void;
    return WITHOUT_GVL_RESULT(args->data->container->create(args->data->container, args->template, args->bdevtype, NULL, args->flags, args->args));
}

/*
 * call-seq:
 *   container.create(template, bdevtype = nil, flags = 0, args = [])
 *
 * Creates a structure for the container according to the given template.
 * This usually consists of downloading and installing a Linux distribution
 * inside the container's rootfs.
 *
 * The +flags+ argument is an OR of +LXC_CREATE_*+ flags.
 */
static VALUE
container_create(int argc, VALUE *argv, VALUE self)
{
    int ret;
    VALUE rb_template, rb_bdevtype, rb_flags, rb_args;
    struct container_create_without_gvl_args args;
    char ** default_args = { NULL };

    args.args = default_args;
    rb_scan_args(argc, argv, "13", &rb_template, &rb_bdevtype, &rb_flags, &rb_args);

    args.template = StringValuePtr(rb_template);
    args.bdevtype = NIL_P(rb_bdevtype) ? NULL : StringValuePtr(rb_bdevtype);
    args.flags = NIL_P(rb_flags) ? 0 : NUM2INT(rb_flags);
    if (!NIL_P(rb_args))
        args.args = ruby_to_c_string_array(rb_args);

    Data_Get_Struct(self, struct container_data, args.data);

    ret = WITHOUT_GVL_CALL(container_create_without_gvl, &args);

    if (!NIL_P(rb_args))
        free_c_string_array(args.args);

    if (!ret)
        rb_raise(Error, "unable to create container");

    return self;
}


static WITHOUT_GVL_RESULT_TYPE
destroy_without_gvl(void *data_void)
{
  struct container_data *data = (struct container_data *)data_void;
  return WITHOUT_GVL_RESULT(data->container->destroy(data->container));
}

/*
 * call-seq:
 *   container.destroy
 *
 * Destroys the container.
 */
static VALUE
container_destroy(VALUE self)
{
    int ret;
    struct container_data *data;

    Data_Get_Struct(self, struct container_data, data);

    ret = WITHOUT_GVL_CALL(destroy_without_gvl, data);
    if (!ret)
        rb_raise(Error, "unable to destroy container");
    return self;
}

static WITHOUT_GVL_RESULT_TYPE
freeze_without_gvl(void *data_void)
{
  struct container_data *data = (struct container_data *)data_void;
  return WITHOUT_GVL_RESULT(data->container->freeze(data->container));
}

/*
 * call-seq:
 *   container.freeze
 *
 * Freezes the container.
 */
static VALUE
container_freeze(VALUE self)
{
    int ret;
    struct container_data *data;

    Data_Get_Struct(self, struct container_data, data);

    ret = WITHOUT_GVL_CALL(freeze_without_gvl, data);
    if (!ret)
        rb_raise(Error, "unable to freeze container");

    return self;
}

/*
 * call-seq:
 *   container.cgroup_item(key)
 *
 * Returns the value corresponding to the given cgroup item configuration.
 */
static VALUE
container_cgroup_item(VALUE self, VALUE rb_key)
{
    int len1, len2;
    char *key, *value;
    struct container_data *data;
    struct lxc_container *container;
    VALUE ret;

    Data_Get_Struct(self, struct container_data, data);
    container = data->container;

    key = StringValuePtr(rb_key);
    len1 = container->get_cgroup_item(container, key, NULL, 0);
    if (len1 < 0)
        rb_raise(Error, "invalid cgroup entry for %s", key);

    value = malloc(sizeof(char) * len1 + 1);
    if (value == NULL)
        rb_raise(rb_eNoMemError, "unable to allocate cgroup value");

    len2 = container->get_cgroup_item(container, key, value, len1 + 1);
    if (len1 != len2) {
        free(value);
        rb_raise(Error, "unable to read cgroup value");
    }
    ret = rb_str_new2(value);
    free(value);

    return ret;
}

/*
 * call-seq:
 *   container.config_item(key)
 *
 * Returns the value corresponding to the given configuration item.
 */
static VALUE
container_config_item(VALUE self, VALUE rb_key)
{
    int len1, len2, mlines;
    char *key, *value;
    struct container_data *data;
    struct lxc_container *container;
    VALUE rb_config;

    Data_Get_Struct(self, struct container_data, data);
    container = data->container;

    key = StringValuePtr(rb_key);
    len1 = container->get_config_item(container, key, NULL, 0);
    if (len1 < 0)
        rb_raise(Error, "invalid configuration key: %s", key);

    value = malloc(sizeof(char) * len1 + 1);
    if (value == NULL)
        rb_raise(rb_eNoMemError, "unable to allocate configuration value");

    len2 = container->get_config_item(container, key, value, len1 + 1);
    if (len1 != len2) {
        free(value);
        rb_raise(Error, "unable to read configuration file");
    }
    rb_config = rb_str_new2(value);
    mlines = value[len2-1] == '\n';
    free(value);

    /* Return a list in case of multiple lines */
    return mlines ? rb_str_split(rb_config, "\n") : rb_config;
}

/*
 * call-seq:
 *   container.config_path
 *
 * Returns the configuration path for the container.
 */
static VALUE
container_config_path(VALUE self)
{
    struct container_data *data;
    Data_Get_Struct(self, struct container_data, data);
    return rb_str_new2(data->container->get_config_path(data->container));
}

/*
 * call-seq:
 *   container.keys(key)
 *
 * Returns a list of valid sub-keys for the given configuration key.
 */
static VALUE
container_keys(VALUE self, VALUE rb_key)
{
    int len1, len2;
    char *key, *value;
    struct container_data *data;
    struct lxc_container *container;
    VALUE rb_keys;

    Data_Get_Struct(self, struct container_data, data);
    container = data->container;

    key = StringValuePtr(rb_key);
    len1 = container->get_keys(container, key, NULL, 0);
    if (len1 < 0)
        rb_raise(Error, "invalid configuration key: %s", key);

    value = malloc(sizeof(char) * len1 + 1);
    if (value == NULL)
        rb_raise(rb_eNoMemError, "unable to allocate configuration value");

    len2 = container->get_keys(container, key, value, len1 + 1);
    if (len1 != len2) {
        free(value);
        rb_raise(Error, "unable to read configuration keys");
    }
    rb_keys = rb_str_new2(value);
    free(value);

    return value[len2-1] == '\n' ?  rb_str_split(rb_keys, "\n") : rb_keys;
}

/*
 * call-seq:
 *   container.interfaces
 *
 * Returns the list of network interfaces of the container.
 */
static VALUE
container_interfaces(VALUE self)
{
    int i, num_interfaces;
    char **interfaces;
    struct container_data *data;
    VALUE rb_interfaces;

    Data_Get_Struct(self, struct container_data, data);

    interfaces = data->container->get_interfaces(data->container);
    if (!interfaces)
        return rb_ary_new();

    for (num_interfaces = 0; interfaces[num_interfaces]; num_interfaces++)
        ;

    rb_interfaces = rb_ary_new2(num_interfaces);
    for (i = 0; i < num_interfaces; i++)
        rb_ary_store(rb_interfaces, i, rb_str_new2(interfaces[i]));

    free_c_string_array(interfaces);

    return rb_interfaces;
}

/*
 * call-seq:
 *   container.ip_addresses
 *
 * Returns the list of IP addresses of the container.
 */
static VALUE
container_ips(int argc, VALUE *argv, VALUE self)
{
    int i, num_ips, scope;
    char *interface, *family;
    char **ips;
    struct container_data *data;
    VALUE rb_ips, rb_interface, rb_family, rb_scope;

    rb_scan_args(argc, argv, "03", &rb_interface, &rb_family, &rb_scope);
    interface = NIL_P(rb_interface) ? NULL : StringValuePtr(rb_interface);
    family    = NIL_P(rb_family)    ? NULL : StringValuePtr(rb_family);
    scope     = NIL_P(rb_scope)     ? 0    : NUM2INT(rb_scope);

    Data_Get_Struct(self, struct container_data, data);

    ips = data->container->get_ips(data->container, interface, family, scope);
    if (ips == NULL)
        return rb_ary_new();

    for (num_ips = 0; ips[num_ips]; num_ips++)
        ;

    rb_ips = rb_ary_new2(num_ips);
    for (i = 0; i < num_ips; i++)
        rb_ary_store(rb_ips, i, rb_str_new2(ips[i]));

    free_c_string_array(ips);

    return rb_ips;
}

struct load_config_without_gvl_args
{
    struct container_data *data;
    char *path;
};

static WITHOUT_GVL_RESULT_TYPE
load_config_without_gvl(void *args_void)
{
    struct load_config_without_gvl_args *args = (struct load_config_without_gvl_args *)args_void;
    return WITHOUT_GVL_RESULT(args->data->container->load_config(args->data->container, args->path));
}

/*
 * call-seq:
 *   container.load_config(config_path = nil)
 *
 * Loads the container's configuration.
 */
static VALUE
container_load_config(int argc, VALUE *argv, VALUE self)
{
    int ret;
    VALUE rb_path;
    struct load_config_without_gvl_args args;

    rb_scan_args(argc, argv, "01", &rb_path);
    args.path = NIL_P(rb_path) ? NULL : StringValuePtr(rb_path);

    Data_Get_Struct(self, struct container_data, args.data);

    ret = WITHOUT_GVL_CALL(load_config_without_gvl, &args);
    if (!ret)
        rb_raise(Error, "unable to load configuration file");

    return self;
}

static WITHOUT_GVL_RESULT_TYPE
reboot_without_gvl(void* data_void)
{
    struct container_data *data = (struct container_data *)data_void;
    return WITHOUT_GVL_RESULT(data->container->reboot(data->container));
}

/*
 * call-seq:
 *   container.reboot
 *
 * Reboots the container.
 */
static VALUE
container_reboot(VALUE self)
{
    int ret;
    struct container_data *data;

    Data_Get_Struct(self, struct container_data, data);

    ret = WITHOUT_GVL_CALL(reboot_without_gvl, data);
    if (!ret)
        rb_raise(Error, "unable to reboot container");

    return self;
}

struct remove_device_node_without_gvl_args
{
    struct container_data *data;
    char *src_path;
    char *dest_path;
};

static WITHOUT_GVL_RESULT_TYPE
remove_device_node_without_gvl(void *args_void)
{
    struct remove_device_node_without_gvl_args *args = (struct remove_device_node_without_gvl_args *)args_void;
    return WITHOUT_GVL_RESULT(args->data->container->remove_device_node(args->data->container, args->src_path, args->dest_path));
}

/*
 * call-seq:
 *   container.remove_device_node(src_path, dest_path = src_path)
 *
 * Removes a device node from the container.
 */
static VALUE
container_remove_device_node(int argc, VALUE *argv, VALUE self)
{
    int ret;
    VALUE rb_src_path, rb_dest_path;
    struct remove_device_node_without_gvl_args args;

    rb_scan_args(argc, argv, "11", &rb_src_path, &rb_dest_path);
    args.src_path = StringValuePtr(rb_src_path);
    args.dest_path = NIL_P(rb_dest_path) ? NULL : StringValuePtr(rb_dest_path);

    Data_Get_Struct(self, struct container_data, args.data);

    ret = WITHOUT_GVL_CALL(remove_device_node_without_gvl, &args);
    if (!ret)
        rb_raise(Error, "unable to remove device node");

    return self;
}

struct rename_without_gvl_args
{
    struct container_data *data;
    char *name;
};

static WITHOUT_GVL_RESULT_TYPE
rename_without_gvl(void *args_void)
{
    struct rename_without_gvl_args *args = (struct rename_without_gvl_args *)args_void;
    return WITHOUT_GVL_RESULT(args->data->container->rename(args->data->container, args->name));
}

/*
 * call-seq:
 *   container.rename(new_name)
 *
 * Renames the container and returns a new +LXC::Container+ instance of
 * the container with the new name.
 */
static VALUE
container_rename(VALUE self, VALUE rb_name)
{
    int ret;
    VALUE rb_args[2];
    struct rename_without_gvl_args args;

    Data_Get_Struct(self, struct container_data, args.data);

    args.name = StringValuePtr(rb_name);

    ret = WITHOUT_GVL_CALL(rename_without_gvl, &args);
    if (!ret)
        rb_raise(Error, "unable to rename container");

    rb_args[0] = rb_name;
    rb_args[1] = Qnil;
    return rb_class_new_instance(2, rb_args, Container);
}

/*
 * call-seq:
 *   container.running_config_item(key)
 *
 * Returns the value corresponding to the given configuration item from a
 * running container.
 */
static VALUE
container_running_config_item(VALUE self, VALUE rb_key)
{
    char *key, *value;
    struct container_data *data;
    struct lxc_container *container;
    VALUE rb_value;

    Data_Get_Struct(self, struct container_data, data);
    container = data->container;

    key = StringValuePtr(rb_key);
    value = container->get_running_config_item(container, key);
    if (value == NULL)
        rb_raise(Error, "unable to read running configuration item: %s", key);

    rb_value = rb_str_new2(value);
    free(value);

    return rb_value;
}

struct save_config_without_gvl_args
{
    struct container_data *data;
    char *path;
};

static WITHOUT_GVL_RESULT_TYPE
save_config_without_gvl(void *args_void)
{
  struct save_config_without_gvl_args *args = (struct save_config_without_gvl_args *)args_void;
  return WITHOUT_GVL_RESULT(args->data->container->save_config(args->data->container, args->path));
}

static VALUE
container_save_config(int argc, VALUE *argv, VALUE self)
{
    int ret;
    VALUE rb_path;
    struct save_config_without_gvl_args args;

    rb_scan_args(argc, argv, "01", &rb_path);
    args.path = NIL_P(rb_path) ? NULL : StringValuePtr(rb_path);

    Data_Get_Struct(self, struct container_data, args.data);

    ret = WITHOUT_GVL_CALL(save_config_without_gvl, &args);
    if (!ret)
        rb_raise(Error, "unable to save configuration file");

    return self;
}

/*
 * call-seq:
 *   container.set_cgroup_item(key, value)
 *
 * Sets the value of a cgroup configuration item.
 */
static VALUE
container_set_cgroup_item(VALUE self, VALUE rb_key, VALUE rb_value)
{
    int ret;
    char *key, *value;
    struct container_data *data;

    key = StringValuePtr(rb_key);
    value = StringValuePtr(rb_value);

    Data_Get_Struct(self, struct container_data, data);

    ret = data->container->set_cgroup_item(data->container, key, value);
    if (!ret)
        rb_raise(Error, "unable to set cgroup item %s to %s", key, value);

    return self;
}

/*
 * call-seq:
 *   container.set_config_item(key, value)
 *
 * Sets the value of a configuration item.
 */
static VALUE
container_set_config_item(VALUE self, VALUE rb_key, VALUE rb_value)
{
    int ret;
    char *key, *value;
    struct container_data *data;

    Data_Get_Struct(self, struct container_data, data);

    key = StringValuePtr(rb_key);
    switch (TYPE(rb_value)) {
    case T_STRING: {
        value = StringValuePtr(rb_value);
        ret = data->container->set_config_item(data->container, key, value);
        if (!ret) {
            rb_raise(Error, "unable to set configuration item %s to %s",
                     key, value);
        }
        return self;
    }
    case T_ARRAY: {
        size_t i;
        size_t len = RARRAY_LEN(rb_value);
        for (i = 0; i < len; i++) {
            VALUE rb_entry = rb_ary_entry(rb_value, i);
            char *entry = StringValuePtr(rb_entry);
            ret = data->container->set_config_item(data->container, key, entry);
            if (!ret) {
                rb_raise(Error, "unable to set configuration item %s to %s",
                        key, entry);
            }
        }
        return self;
    }
    default:
        rb_raise(Error, "configuration value must be either string or array");
    }
}

/*
 * call-seq:
 *   container.config_path = path
 *
 * Sets the container configuration path.
 */
static VALUE
container_set_config_path(VALUE self, VALUE rb_path)
{
    int ret;
    char *path;
    struct container_data *data;

    path = StringValuePtr(rb_path);
    Data_Get_Struct(self, struct container_data, data);

    ret = data->container->set_config_path(data->container, path);
    if (!ret)
        rb_raise(Error, "unable to set configuration path to %s", path);

    return self;
}

struct shutdown_without_gvl_args
{
    struct container_data *data;
    int timeout;
};

static WITHOUT_GVL_RESULT_TYPE
shutdown_without_gvl(void* args_void)
{
    struct shutdown_without_gvl_args *args = (struct shutdown_without_gvl_args *)args_void;
    return WITHOUT_GVL_RESULT(args->data->container->shutdown(args->data->container, args->timeout));
}

/*
 * call-seq:
 *   container.shutdown(timeout = -1)
 *
 * Shuts down the container, optionally waiting for +timeout+ seconds. If
 * +timeout+ is +-1+, wait as long as necessary for the container to
 * shutdown.
 */
static VALUE
container_shutdown(int argc, VALUE *argv, VALUE self)
{
    int ret;
    VALUE rb_timeout;
    struct shutdown_without_gvl_args args;

    rb_scan_args(argc, argv, "01", &rb_timeout);

    Data_Get_Struct(self, struct container_data, args.data);

    args.timeout = NIL_P(rb_timeout) ? -1 : NUM2INT(rb_timeout);

    ret = WITHOUT_GVL_CALL(shutdown_without_gvl, &args);
    if (!ret)
        rb_raise(Error, "unable to shutdown container");

    return self;
}

struct snapshot_without_gvl_args
{
    struct container_data *data;
    char *path;
};

static WITHOUT_GVL_RESULT_TYPE
snapshot_without_gvl(void* args_void)
{
    struct snapshot_without_gvl_args *args = (struct snapshot_without_gvl_args *)args_void;
    return WITHOUT_GVL_RESULT(args->data->container->snapshot(args->data->container, args->path));
}

/*
 * call-seq:
 *   container.snapshot(path = nil)
 *
 * Creates a snapshot of the container. Returns the snapshot name.
 */
static VALUE
container_snapshot(int argc, VALUE *argv, VALUE self)
{
    int ret;
    char new_name[20];
    VALUE rb_path;
    struct snapshot_without_gvl_args args;

    rb_scan_args(argc, argv, "01", &rb_path);
    args.path = NIL_P(rb_path) ? NULL : StringValuePtr(rb_path);

    Data_Get_Struct(self, struct container_data, args.data);

    ret = WITHOUT_GVL_CALL(snapshot_without_gvl, &args);
    if (ret < 0)
        rb_raise(Error, "unable to snapshot container");

    ret = snprintf(new_name, 20, "snap%d", ret);
    if (ret < 0 || ret >= 20)
        rb_raise(Error, "unable to snapshot container");

    return rb_str_new2(new_name);
}

struct snapshot_destroy_without_gvl_args
{
    struct container_data *data;
    char *name;
};

static WITHOUT_GVL_RESULT_TYPE
snapshot_destroy_without_gvl(void *args_void)
{
    struct snapshot_destroy_without_gvl_args *args = (struct snapshot_destroy_without_gvl_args *)args_void;
    return WITHOUT_GVL_RESULT(args->data->container->snapshot_destroy(args->data->container, args->name));
}

/*
 * call-seq:
 *   container.snapshot_destroy(name)
 *
 * Destroys the given snapshot.
 */
static VALUE
container_snapshot_destroy(VALUE self, VALUE rb_name)
{
    int ret;
    struct snapshot_destroy_without_gvl_args args;

    Data_Get_Struct(self, struct container_data, args.data);

    args.name = StringValuePtr(rb_name);

    ret = WITHOUT_GVL_CALL(snapshot_destroy_without_gvl, &args);
    if (!ret)
        rb_raise(Error, "unable to destroy snapshot");

    return self;
}

struct snapshot_list_without_gvl_args
{
    struct container_data *data;
    struct lxc_snapshot *snapshots;
};

static WITHOUT_GVL_RESULT_TYPE
snapshot_list_without_gvl(void *args_void)
{
    struct snapshot_list_without_gvl_args *args = (struct snapshot_list_without_gvl_args *)args_void;
    return WITHOUT_GVL_RESULT(args->data->container->snapshot_list(args->data->container, &args->snapshots));
}

/*
 * call-seq:
 *   container.snapshot_list
 *
 * Returns a list of existing snapshots for the container.
 */
static VALUE
container_snapshot_list(VALUE self)
{
    int i, num_snapshots;
    VALUE rb_snapshots;
    struct snapshot_list_without_gvl_args args;

    Data_Get_Struct(self, struct container_data, args.data);

    num_snapshots = WITHOUT_GVL_CALL(snapshot_list_without_gvl, &args);
    if (num_snapshots < 0)
        rb_raise(Error, "unable to list snapshots");

    rb_snapshots = rb_ary_new2(num_snapshots);
    for (i = 0; i < num_snapshots; i++) {
        VALUE attrs = rb_ary_new2(4);
        rb_ary_store(attrs, 0, rb_str_new2(args.snapshots[i].name));
        rb_ary_store(attrs, 1, rb_str_new2(args.snapshots[i].comment_pathname));
        rb_ary_store(attrs, 2, rb_str_new2(args.snapshots[i].timestamp));
        rb_ary_store(attrs, 3, rb_str_new2(args.snapshots[i].lxcpath));
        args.snapshots[i].free(&args.snapshots[i]);
        rb_ary_store(rb_snapshots, i, attrs);
    }

    return rb_snapshots;
}

struct snapshot_restore_without_gvl_args
{
    struct container_data *data;
    char *name;
    char *new_name;
};

static WITHOUT_GVL_RESULT_TYPE
snapshot_restore_without_gvl(void *args_void)
{
    struct snapshot_restore_without_gvl_args *args = (struct snapshot_restore_without_gvl_args *)args_void;
    return WITHOUT_GVL_RESULT(args->data->container->snapshot_restore(args->data->container, args->name, args->new_name));
}

/*
 * call-seq:
 *   container.snapshot_restore(name, new_name = nil)
 *
 * Restores the given snapshot.
 */
static VALUE
container_snapshot_restore(int argc, VALUE *argv, VALUE self)
{
    int ret;
    struct snapshot_restore_without_gvl_args args;
    VALUE rb_name, rb_new_name;

    rb_scan_args(argc, argv, "11", &rb_name, &rb_new_name);
    args.name = StringValuePtr(rb_name);
    args.new_name = NIL_P(rb_new_name) ? NULL : StringValuePtr(rb_new_name);

    Data_Get_Struct(self, struct container_data, args.data);

    ret = WITHOUT_GVL_CALL(snapshot_restore_without_gvl, &args);
    if (!ret)
        rb_raise(Error, "unable to restore snapshot");

    return self;
}


struct start_without_gvl_args
{
    struct container_data *data;
    int use_init;
    int daemonize;
    int close_fds;
    char **args;
};

static WITHOUT_GVL_RESULT_TYPE
start_without_gvl(void *args_void)
{
    struct start_without_gvl_args *args = (struct start_without_gvl_args *)args_void;
    struct lxc_container *container = args->data->container;
    container->want_close_all_fds(container, args->close_fds);
    container->want_daemonize(container, args->daemonize);
    return WITHOUT_GVL_RESULT(container->start(container, args->use_init, args->args));
}

/*
 * call-seq:
 *   container.start(opts = {})
 *
 * Starts the container. The options hash may contain the following keys.
 *
 * * +:use_init+
 * * +:daemonize+
 * * +:close_fds+
 * * +:args+
 */
static VALUE
container_start(int argc, VALUE *argv, VALUE self)
{
    int ret;
    VALUE rb_use_init, rb_daemonize, rb_close_fds, rb_args, rb_opts;
    struct start_without_gvl_args args;

    args.use_init = 0;
    args.daemonize = 1;
    args.close_fds = 0;
    args.args = NULL;
    rb_args = Qnil;

    rb_scan_args(argc, argv, "01", &rb_opts);
    if (!NIL_P(rb_opts)) {
        Check_Type(rb_opts, T_HASH);
        rb_use_init = rb_hash_aref(rb_opts, SYMBOL("use_init"));
        args.use_init = (rb_use_init != Qnil) && (rb_use_init != Qfalse);

        rb_daemonize = rb_hash_aref(rb_opts, SYMBOL("daemonize"));
        args.daemonize = (rb_daemonize != Qnil) && (rb_daemonize != Qfalse);

        rb_close_fds = rb_hash_aref(rb_opts, SYMBOL("close_fds"));
        args.close_fds = (rb_close_fds != Qnil) && (rb_close_fds != Qfalse);

        rb_args = rb_hash_aref(rb_opts, SYMBOL("args"));
        args.args = NIL_P(rb_args) ? NULL : ruby_to_c_string_array(rb_args);
    }

    Data_Get_Struct(self, struct container_data, args.data);

    ret = WITHOUT_GVL_CALL(start_without_gvl, &args);

    if (!NIL_P(rb_args))
        free_c_string_array(args.args);

    if (!ret)
        rb_raise(Error, "unable to start container");

    return self;
}

static WITHOUT_GVL_RESULT_TYPE
stop_without_gvl(void *data_void)
{
    struct container_data *data = (struct container_data *)data_void;
    return WITHOUT_GVL_RESULT(data->container->stop(data->container));
}

/*
 * call-seq:
 *   container.stop
 *
 * Stops the container.
 */
static VALUE
container_stop(VALUE self)
{
    int ret;
    struct container_data *data;

    Data_Get_Struct(self, struct container_data, data);

    ret = WITHOUT_GVL_CALL(stop_without_gvl, data);
    if (!ret)
        rb_raise(Error, "unable to stop container");

    return self;
}

static WITHOUT_GVL_RESULT_TYPE
unfreeze_without_gvl(void *data_void)
{
  struct container_data *data = (struct container_data *)data_void;
  return WITHOUT_GVL_RESULT(data->container->unfreeze(data->container));
}

/*
 * call-seq:
 *   container.unfreeze
 *
 * Thaws a frozen container.
 */
static VALUE
container_unfreeze(VALUE self)
{
    int ret;
    struct container_data *data;

    Data_Get_Struct(self, struct container_data, data);

    ret = WITHOUT_GVL_CALL(unfreeze_without_gvl, data);
    if (!ret)
        rb_raise(Error, "unable to unfreeze container: #{lxc_strerror(ret)}");

    return self;
}

struct wait_without_gvl_args
{
    struct container_data *data;
    int timeout;
    char *state;
};

static WITHOUT_GVL_RESULT_TYPE
wait_without_gvl(void *args_void)
{
    struct wait_without_gvl_args *args = (struct wait_without_gvl_args *)args_void;
    return WITHOUT_GVL_RESULT(args->data->container->wait(args->data->container, args->state, args->timeout));
}

/*
 * call-seq:
 *   container.wait(state, timeout = -1)
 *
 * Waits for +timeout+ seconds (or as long as necessary if +timeout+ is +-1+)
 * until the container's state becomes +state+.
 */
static VALUE
container_wait(int argc, VALUE *argv, VALUE self)
{
    int ret;
    VALUE rb_state_str, rb_state, rb_timeout;
    struct wait_without_gvl_args args;

    rb_scan_args(argc, argv, "11", &rb_state, &rb_timeout);

    rb_state_str = rb_funcall(rb_state, rb_intern("to_s"), 0);
    rb_state_str = rb_funcall(rb_state_str, rb_intern("upcase"), 0);
    args.state = StringValuePtr(rb_state_str);

    args.timeout = NIL_P(rb_timeout) ? -1 : NUM2INT(rb_timeout);

    Data_Get_Struct(self, struct container_data, args.data);

    ret = WITHOUT_GVL_CALL(wait_without_gvl, &args);
    if (!ret)
        rb_raise(Error, "error waiting for container");

    return self;
}

void
Init_lxc(void)
{
    VALUE LXC = rb_define_module("LXC");

    rb_define_singleton_method(LXC, "arch_to_personality",
                               lxc_arch_to_personality, 1);
    rb_define_singleton_method(LXC, "run_command", lxc_run_command, 1);
    rb_define_singleton_method(LXC, "run_shell", lxc_run_shell, 0);
    rb_define_singleton_method(LXC, "global_config_item",
                               lxc_global_config_item, 1);
    rb_define_singleton_method(LXC, "version", lxc_version, 0);
    rb_define_singleton_method(LXC, "list_containers", lxc_list_containers, -1);

    Container = rb_define_class_under(LXC, "Container", rb_cObject);
    rb_define_alloc_func(Container, container_alloc);

    rb_define_method(Container, "initialize", container_initialize, -1);

    rb_define_method(Container, "config_file_name",
                     container_config_file_name, 0);
    rb_define_method(Container, "controllable?", container_controllable_p, 0);
    rb_define_method(Container, "defined?", container_defined_p, 0);
    rb_define_method(Container, "init_pid", container_init_pid, 0);
    rb_define_method(Container, "name", container_name, 0);
    rb_define_method(Container, "running?", container_running_p, 0);
    rb_define_method(Container, "state", container_state, 0);

    rb_define_method(Container, "add_device_node",
                     container_add_device_node, -1);
    rb_define_method(Container, "attach", container_attach, -1);
    rb_define_method(Container, "clear_config", container_clear_config, -1);
    rb_define_method(Container, "clear_config_item",
                     container_clear_config_item, 1);
    rb_define_method(Container, "clone", container_clone, -1);
    rb_define_method(Container, "console", container_console, -1);
    rb_define_method(Container, "console_fd", container_console_fd, -1);
    rb_define_method(Container, "create", container_create, -1);
    rb_define_method(Container, "destroy", container_destroy, 0);
    rb_define_method(Container, "freeze", container_freeze, 0);
    rb_define_method(Container, "cgroup_item", container_cgroup_item, 1);
    rb_define_method(Container, "config_item", container_config_item, 1);
    rb_define_method(Container, "config_path", container_config_path, 0);
    rb_define_method(Container, "keys", container_keys, 1);
    rb_define_method(Container, "interfaces", container_interfaces, 0);
    rb_define_method(Container, "ip_addresses", container_ips, -1);
    rb_define_method(Container, "load_config", container_load_config, -1);
    rb_define_method(Container, "reboot", container_reboot, 0);
    rb_define_method(Container, "remove_device_node",
                     container_remove_device_node, -1);
    rb_define_method(Container, "rename", container_rename, 1);
    rb_define_method(Container, "running_config_item",
                     container_running_config_item, 1);
    rb_define_method(Container, "save_config", container_save_config, -1);
    rb_define_method(Container, "set_cgroup_item",
                     container_set_cgroup_item, 2);
    rb_define_method(Container, "set_config_item",
                     container_set_config_item, 2);
    rb_define_method(Container, "config_path=", container_set_config_path, 1);
    rb_define_method(Container, "shutdown", container_shutdown, -1);
    rb_define_method(Container, "snapshot", container_snapshot, -1);
    rb_define_method(Container, "snapshot_destroy",
                     container_snapshot_destroy, 1);
    rb_define_method(Container, "snapshot_list", container_snapshot_list, 0);
    rb_define_method(Container, "snapshot_restore",
                     container_snapshot_restore, -1);
    rb_define_method(Container, "start", container_start, -1);
    rb_define_method(Container, "stop", container_stop, 0);
    rb_define_method(Container, "unfreeze", container_unfreeze, 0);
    rb_define_method(Container, "wait", container_wait, -1);

#define LXC_CONTAINER_CONST(c) rb_define_const(LXC, #c, LONG2NUM(c))

    /* namespace flags */
    LXC_CONTAINER_CONST(CLONE_NEWUTS);
    LXC_CONTAINER_CONST(CLONE_NEWIPC);
    LXC_CONTAINER_CONST(CLONE_NEWUSER);
    LXC_CONTAINER_CONST(CLONE_NEWPID);
    LXC_CONTAINER_CONST(CLONE_NEWNET);
    LXC_CONTAINER_CONST(CLONE_NEWNS);

    /* attach: environment variable handling */
    LXC_CONTAINER_CONST(LXC_ATTACH_CLEAR_ENV);
    LXC_CONTAINER_CONST(LXC_ATTACH_KEEP_ENV);

    /* attach: attach options */
    LXC_CONTAINER_CONST(LXC_ATTACH_DEFAULT);
    LXC_CONTAINER_CONST(LXC_ATTACH_DROP_CAPABILITIES);
    LXC_CONTAINER_CONST(LXC_ATTACH_LSM_EXEC);
    LXC_CONTAINER_CONST(LXC_ATTACH_LSM_NOW);
    LXC_CONTAINER_CONST(LXC_ATTACH_MOVE_TO_CGROUP);
    LXC_CONTAINER_CONST(LXC_ATTACH_REMOUNT_PROC_SYS);
    LXC_CONTAINER_CONST(LXC_ATTACH_SET_PERSONALITY);

    /* clone: clone flags */
    LXC_CONTAINER_CONST(LXC_CLONE_KEEPBDEVTYPE);
    LXC_CONTAINER_CONST(LXC_CLONE_KEEPMACADDR);
    LXC_CONTAINER_CONST(LXC_CLONE_KEEPNAME);
    LXC_CONTAINER_CONST(LXC_CLONE_MAYBE_SNAPSHOT);
    LXC_CONTAINER_CONST(LXC_CLONE_SNAPSHOT);

    /* create: create flags */
    LXC_CONTAINER_CONST(LXC_CREATE_QUIET);

#undef LXC_CONTAINER_CONST

    Error = rb_define_class_under(LXC, "Error", rb_eStandardError);
}
