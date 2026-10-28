#ifndef LOADER_H
#define LOADER_H

/* Load a named program and create its task.
 * Returns the task ID on success, or a negative error code. */
int loader_program_run(const char *name);

#endif
