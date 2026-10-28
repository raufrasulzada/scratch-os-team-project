#include <stdint.h>

#include "kernel/task.h"
#include "lib/syscalls.h"

extern uint32_t _shell_part_start[];
extern uint32_t _shell_stack_top[];
extern uint32_t _shell_part_end[];
extern uint32_t _shell_data_start[];
extern uint32_t _shell_data_end[];
extern const uint32_t _shell_data_load[];

static char input[32];
static int previous_terminator;

static unsigned text_length(const char *text)
{
    unsigned length = 0;
    while (text[length] != '\0')
        length++;
    return length;
}

static void write_all(const char *text, unsigned length)
{
    unsigned sent = 0;

    while (sent < length) {
        int written = sys_write(text + sent, length - sent);

        if (written < 0)
            return;

        if (written == 0) {
            task_yield();
            continue;
        }

        sent += (unsigned)written;
    }
}

static void write_text(const char *text)
{
    write_all(text, text_length(text));
}

static int line_equals(const char *line, unsigned length,
                       const char *expected)
{
    unsigned i = 0;

    while (expected[i] != '\0') {
        if (i >= length || line[i] != expected[i])
            return 0;
        i++;
    }

    return i == length;
}

static void shell_ls(void)
{
    int count = sys_image_count();

    if (count < 0) {
        write_text("error: no valid image\n");
        return;
    }

    for (unsigned i = 0; i < (unsigned)count; i++) {
        char name[16];

        if (sys_image_name(i, name, sizeof(name)) < 0) {
            write_text("error: no valid image\n");
            return;
        }

        write_all(name, text_length(name));
        write_text("\n");
    }
}

static void shell_run(void)
{
    int id = sys_program_run(&input[4]);

    if (id >= 0) {
        /* The kernel prints the exit/fault message. Wait without
         * displaying another prompt while the program is running. */
        (void)sys_program_wait(id);
    } else if (id == -2) {
        write_text("error: program not found\n");
    } else if (id == -3) {
        write_text("error: no free slot\n");
    } else {
        write_text("error: program cannot be loaded\n");
    }
}

static void process_line(unsigned length)
{
    if (line_equals(input, length, "help")) {
        write_text("help - show commands\n"
                   "ls - list programs\n"
                   "run <name> - run a program\n");
    } else if (line_equals(input, length, "ls")) {
        shell_ls();
    } else if (length > 4
               && input[0] == 'r'
               && input[1] == 'u'
               && input[2] == 'n'
               && input[3] == ' ') {
        shell_run();
    } else {
        write_text("error: unknown command\n");
    }
}

static void shell_task(void)
{
    for (;;) {
        write_text("scratch> ");

        unsigned length = 0;
        input[0] = '\0';

        for (;;) {
            int ch = sys_read();

            if (ch < 0) {
                task_yield();
                continue;
            }

            if (ch == '\r' || ch == '\n') {
                /* Treat CRLF and LFCR as one line ending. */
                if ((ch == '\n' && previous_terminator == '\r') ||
                    (ch == '\r' && previous_terminator == '\n')) {
                    previous_terminator = 0;
                    continue;
                }

                previous_terminator = ch;
                write_text("\n");
                input[length] = '\0';
                process_line(length);
                break;
            }
            previous_terminator = 0;

            /* Store and echo at most 31 characters. Drop overflow
             * silently until the end of this line. */
            if (length < 31) {
                input[length++] = (char)ch;
                input[length] = '\0';
                write_all(&input[length - 1], 1);
            }
        }
    }
}

void task_project_configure(void)
{
    task_configure_shell(
        "shell",
        shell_task,
        _shell_stack_top,
        (uint32_t)_shell_part_start,
        (uint32_t)_shell_part_end,
        _shell_data_start,
        _shell_data_end,
        _shell_data_load
    );
}
