#define __STDC_WANT_LIB_EXT2__ 1
#define _GNU_SOURCE 1

#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>

/*
 * Returns true if 'p' is a pointer type, false otherwise.
 */
#define is_pointer(p)  (__builtin_classify_type(p) == 5)

/*
 * Returns reference of 'x' if x is not a pointer, 'x' otherwise.
 * Kind of like autodereferencing, but backwards.
 * Ex: int x; assert(maybe_ref(x) == maybe_ref(&x));
 */
#define maybe_ref(x) __builtin_choose_expr(is_pointer((x)), (x), &(x))

/*
 * Creates a struct with the given type T to mimic a C++ vector.
 */
#define Vec_define(T, name) typedef struct { T *data; int len; int cap; } name

#define len(x) (maybe_ref((x))->len)
#define cap(x) (maybe_ref((x))->cap)
#define data(x) (maybe_ref((x))->data)
#define first(x) (data((x))[0])
#define last(x) (data((x))[len((x))-1])

/*
 * Used to index an array 'v' with bounds checking.
 */
#define at(v, index) data((v))[(void)assert((index) < len((v))), (index)]

/*
 * Increases the capacity of the vec.
 */
#define grow(vec, arena)                                                \
    (cap(vec) = (cap(vec) == 0 ? 4 : cap(vec) * 2),                     \
     data(vec)=Arena_realloc(maybe_ref(arena), data(vec), cap(vec), sizeof(*data(vec))))

/*
 * Returns a pointer to the next free element in the vec. Allocates more memory if needed.
 */
#define append(vec, arena)                      \
    (len((vec)) >= cap((vec))                   \
     ? (grow((vec), (arena)) + len((vec))++)    \
     : (data((vec)) + len((vec))++))

typedef enum {
    Redirect_Pipe = '|',
    Redirect_Stdout = '>',
    Redirect_Stdin = '<',
} Redirect;

typedef char* cstr;

Vec_define(char, str);
Vec_define(cstr, Vec_cstr);
Vec_define(Vec_cstr, Vec_Vec_cstr);
Vec_define(void*, Arena);
Vec_define(Redirect, Vec_Redirect);

/*
  .programs: An array of programs to execute with their arguments.
  .redirects: An array of the IO redirects that would be placed in between each program.
 */
typedef struct {
    Vec_Vec_cstr programs;
    Vec_Redirect redirects;
} Data;

/*
 * Adds a pointer to the arena for safekeeping.
 */
void Arena_append(Arena *arena, void *p);

/*
 * Allocates an array on the heap if 'p' is NULL, reallocates the array 'p' otherwise.
 * Returns a pointer to an array of length 'n' with element size 'size'.
 * Places the pointer into 'arena' for safekeeping.
 */
void *Arena_realloc(Arena *arena, void *p, int n, int size);

/*
 * Frees all pointer saved in the arena, including the arena itself.
 */
void Arena_deinit(Arena *arena);

/*
 * Returns true if 'x' is a whitespace character, false otherwise.
 */
bool is_whitespace(char x);

/*
 * Returns true if 'x' is an IO redirect, false otherwise.
 */
bool is_redirect(cstr x);

/*
 * Splits 'input' into an array of substrings based on whitespace.
 * Modifies 'input' by placing a null terminator at the end of each substring.
 * Each element in the array is a pointer to first character of the substring.
 */
Vec_cstr split_string_on_whitespace(str input, Arena *a);

/*
 * Splits 'tokens' into subarrays of tokens based on the redirect character.
 * Each subarray is null terminated.
 * Subarrays with an "&" token as the last element have the null terminator placed before that element.
 * Each redirect token is placed into a separate array.
 */
Data split_tokens_on_redirect(Vec_cstr tokens, Arena *a);

/*
 * Waits for the user to enter a line from the stdin.
 * Returns that line.
 */
str wait_for_user_input(Arena *a);

/*
 * Changes the shell's current directory and handles any errors (in the cd command).
 */
void change_directory(cstr *path, Vec_cstr program);

/*
  Exit the shell and handle any errors (in the exit command).
 */
void exit_shell(Vec_cstr program);

/*
 * The '>' redirect must be last.
 * The '<' redirect must be by itself.
 * There can be any number of '|' redirects one after the other.
 */
bool has_valid_redirect_pattern(Vec_Redirect r);

/*
 * Calls exec on the program and handles any errors.
 */
void execute_program(Vec_cstr program);

/*
 * Wait for the process with 'pid' to exit if the last element of 'program' is not an "&".
 * Otherwise, continue execution of the shell.
 */
void maybe_put_process_in_background(Vec_cstr program, int pid);

/*
 * Handles logic for executing a chain of programs with IO redirects.
 */
void execute_programs(Data d);

/*
 * Decides if the input is an internal command, a single program, or a chain of programs with IO redirects.
 */
void eval_input(cstr *path, Data d);

/*
 * Prints the message of the day.
 */
void motd(void);

/*
 * Prints the terminal prompt.
 */
void print_prompt(char *path);

void Arena_append(Arena *arena, void *p) {
    if (len(arena) >= cap(arena)) {
        cap(arena) = cap(arena) == 0 ? 4 : cap(arena) * 2;
        data(arena) = realloc(data(arena), cap(arena) * sizeof(void*));
    }
    len(arena) += 1;
    last(arena) = p;
}

void *Arena_realloc(Arena *arena, void *p, int n, int size) {
    if (p != NULL) {
        for (int i = 0; i < len(arena); ++i) {
            if (at(arena, i) == p) {
                void *new_p = realloc(p, n * size);
                at(arena, i) = new_p;
                return new_p;
            }
        }
        fprintf(stderr, "Don't do that, pls\n");
        exit(1);
    } else {
        void *new_p = calloc(n, size);
        Arena_append(arena, new_p);
        return new_p;
    }
}

void Arena_deinit(Arena *arena) {
    for (int i = 0; i < len(arena); ++i) free(at(arena, i));
    free(data(arena));
}

bool is_whitespace(char x) { return x == ' ' || x == '\t' || x == '\n'; }
bool is_redirect(cstr x) { return *x == Redirect_Pipe || *x == Redirect_Stdout || *x == Redirect_Stdin; }

Vec_cstr split_string_on_whitespace(str input, Arena *a) {
    Vec_cstr out = {0};

    for (int i = 0; i < len(input); ++i) {
        for (;; ++i) {
            if (i >= len(input)) return out;
            else if (!is_whitespace(at(input, i))) break;
        }

        *append(out, a) = &at(input, i);

        for (;; ++i) {
            if (i >= len(input)) return out;
            else if (is_whitespace(at(input, i))) break;
        }
        at(input, i) = '\0'; // replace whitespace with null terminator
    }

    return out;
}

Data split_tokens_on_redirect(Vec_cstr tokens, Arena *a) {
    Vec_Vec_cstr programs = {0}; 
    Vec_Redirect redirects = {0};

    for (int i = 0; i < len(tokens); ++i) {
        for (; i < len(tokens) && is_redirect(at(tokens, i)); ++i);
        
        Vec_cstr program = {0};
        
        for (; i < len(tokens) && !is_redirect(at(tokens, i)); ++i) {
            *append(program, a) = at(tokens, i);
        }

        if (0 == strncmp("&", last(program), 1)) {
            last(program) = NULL;
            *append(program, a) = "&"; // put the ampersand after the null terminator, so it isn't part of the program's arguments
        } else {
            *append(program, a) = NULL;
        }
        
        *append(programs, a) = program;
        
        if (i < len(tokens)) {
            char token = *at(tokens, i);
            *append(redirects, a) = (Redirect)token;
        } else {
            break;
        }
    }

    return (Data) { programs, redirects };
}


str wait_for_user_input(Arena *a) {
    char *data = NULL;
    size_t bufsize = 0;
    size_t len = getline(&data, &bufsize, stdin);
    Arena_append(a, data);
    return (str) { data, len, len };
}

void change_directory(cstr *path, Vec_cstr program) {
    if (len(program) == 3) {
        int ret = chdir(at(program, 1));
        if (ret == 0) {
            free(*path);
            *path = get_current_dir_name();
        } else {
            fprintf(stderr, "\e[31mCould not go to directory\e[0m '%s'\n", at(program, 1));
        }
    } else {
        fprintf(stderr, "\e[31mToo many args for cd command\e[0m\n");
    }
}

void exit_shell(Vec_cstr program) {
    if (len(program) == 2) {
        printf("Exiting ... Have a nice day!\n");
        exit(0);
    } else {
        printf("\e[31mToo many arguments for exit command\e[0m\n");
    }
}

bool has_valid_redirect_pattern(Vec_Redirect r) {
    if (len(r) == 0)
        return true;
    
    if (first(r) == Redirect_Stdin) {
        if (len(r) == 1)
            return true;
        else
            return false;
    }

    for (int i = 0; i < len(r)-1; ++i) {
        if (at(r, i) != Redirect_Pipe) return false;
    }

    if (last(r) == Redirect_Stdout || last(r) == Redirect_Pipe)
        return true;
    else
        return false;
}

void execute_program(Vec_cstr program) {
    int ret = execvp(first(program), data(program));
    if (ret == -1) {
        fprintf(stderr, "\e[31mUnrecognized command or program:\e[0m '%s'\n", at(program, 0));
        exit(1);
    }
}

void maybe_put_process_in_background(Vec_cstr program, int pid) {
    cstr last = last(program);
    if ((last == NULL) || (0 != strncmp("&", last, 1))) {
        printf("\e[1m--- Starting program ---\e[0m\n");
        waitpid(pid, NULL, 0);
        printf("\e[1m--- Program ended ---\e[0m\n");
    } else {
        printf("Running job in background ...\n");
    }
}

void execute_programs(Data d) {
    if (at(d.redirects, 0) == Redirect_Stdin) {
        cstr file = first(last(d.programs));
        FILE *fp = fopen(file, "r");
        int fd = fileno(fp);

        int pd[2];
        pipe(pd);
        int write_end = pd[1];
        int read_end = pd[0];

        char buf[64];
        for (;;) {
            int ret = read(fd, buf, 64);
            if (ret == 0 || ret == -1) break;
            write(write_end, buf, ret);
        }
        
        close(write_end);
        fclose(fp);
        
        Vec_cstr program = first(d.programs);
        int pid = fork();
        if (pid == 0) {
            dup2(read_end, STDIN_FILENO);
            execute_program(program);
        }

        maybe_put_process_in_background(program, pid);
        
        return;
    }

    int prev_read_end = -1;
    for (int i = 0; i < len(d.programs) - 1; ++i) {
        int pd[2];
        pipe(pd);
        int write_end = pd[1];
        int read_end = pd[0];

        int pid = fork();
        if (pid == 0) {
            if (prev_read_end != -1) dup2(prev_read_end, STDIN_FILENO);
            dup2(write_end, STDOUT_FILENO);
            execute_program(at(d.programs, i));
        }

        waitpid(pid, NULL, 0);
        close(write_end);
        prev_read_end = read_end;
    }

    Redirect r = last(d.redirects);
    
    if (r == Redirect_Pipe) {
        Vec_cstr p = last(d.programs);

        int pid = fork();
        if (pid == 0) {
            dup2(prev_read_end, STDIN_FILENO);
            execute_program(p);
        }

        maybe_put_process_in_background(p, pid);
    } else if (r == Redirect_Stdout) {
        cstr file = first(last(d.programs)); 
        FILE *fp = fopen(file, "w");
        int fd = fileno(fp);

        char buf[64];
        for (;;) {
            int ret = read(prev_read_end, buf, 64);
            if (ret == 0 || ret == -1) break;
            write(fd, buf, ret);
        }
        
        fclose(fp);
    }
}

void eval_input(cstr *path, Data d) {
    if (len(d.programs) == 1) {
        Vec_cstr program = first(d.programs);
        
        if (strncmp("exit", first(program), 4) == 0) {
            exit_shell(program);
        } else if (strncmp("cd", first(program), 2) == 0) {
            change_directory(path, program);
        } else {
            int pid = fork();
            if (pid == 0) {
                execute_program(program);
            }

            maybe_put_process_in_background(program, pid);
        }
    } else {
        execute_programs(d);
    }
}

/* https://www.asciiart.eu/animals/reptiles/dinosaurs */
void motd(void) {
    printf(
        "                             *                    .-=-.               *                 \n"
        "             *   .                 +           .-\"     \"-.                   *          \n"
        "   +.                `   +                    :           :                             \n"
        "            ,                             '  :             :         *       *          \n"
        "                     *           ,           :             :                            \n"
        "      ,                   -              ,    :           :                             \n"
        "                                               '.       .'     +                        \n"
        "                                                 '-._.-'              '                 \n"
        "                      `            `                                                    \n"
        "                                                                                        \n"
        "                                                                 ./=/-.\\                \n"
        "     ,.=.__'i '=\\._  /-' -.._.i'- .__=^.^/+._ =\\._  /=,__.-=/..-'        '-.            \n"
        " .-'\\=    '=.  .-' '/       ._y._     ./     _ ._.-' '            ._            - .     \n"
        "'                  .._+  .=\\  ._=/   \\=. \\=.  '                    \\'-. ._=/'-..        \n"
        "    '.__/='     .-t    '-.'       /-         '-      .-'""-.    /\\=..-/=  p ._\"         \n"
        "             \\.=   '\\=.                           .-'       :     '. . /()'. -\\         \n"
        "     =/    ='             _.--.._               .'         o o     =/()   : \\=.-=       \n"
        "   .'  '-/'           .--'       '--..       .-'   ..--._     :   /=   \\ / ()=\\  '      \n"
        "                    .'                '-.._.'    .'      '_   :  =/()  : :  ()\\=        \n"
        "                  .'                           .'          :__.   '    \\ /              \n"
        "                 :                          .-'                       :   :             \n"
        "                :                        .-'                           \\ /              \n"
        "         /=,.   :                       :             .,\\=      .; i   : :              \n"
        " fsc            :                     .'          ,--'      /=-.    .  \\ /              \n"
        "          'j    '     _            .-:    ,-=/        =\\.          t  :   :             \n"
        "            '.   \\  !  :--..__.   : !                                  \\ /              \n"
        "             :    :  :  '.     \\  ! '-.      .'\\           ,f'         : :              \n"
        "         ,\\=.'    :.  '.u'      i  '-.u                   '   :=/      \\ /    o         \n"
        "  .               '.uuu'         '.uu'              .-=/           .  :   :  '|v'       \n"
        "/' '.-;\\.  ,-/=                                                  '\\|.- \\ /              \n"
        "                       .=       \\=,_      /[-'            '/=              ()           \n"
        "                   .-'/   /='  '[       '\n"
        "Welcome to Dino Bash\n"
        );
}

void print_prompt(char *path) {
    printf("[\e[32m%s\e[0m]\n> ", path);
}

int main(void) {
    cstr path = get_current_dir_name();

    // removes any child processes that haven't terminated.
    // Used to handle background processes.
    signal(SIGCHLD, SIG_IGN); 
    
    motd();
    for (;;) {
        Arena arena = {0};
        
        print_prompt(path);
        str input = wait_for_user_input(&arena);
        
        Vec_cstr tokens = split_string_on_whitespace(input, &arena);
        Data d = split_tokens_on_redirect(tokens, &arena);

        if (has_valid_redirect_pattern(d.redirects)) {
            if (len(d.programs) > 0)
                eval_input(&path, d);
        } else {
            fprintf(stderr, "\e[31mInvalid redirect pattern! Check the rules!\e[0m\n");
        }

        Arena_deinit(&arena);
    }
}
