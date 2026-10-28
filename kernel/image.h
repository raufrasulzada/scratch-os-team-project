#ifndef IMAGE_H
#define IMAGE_H

#include <stdint.h>

/* Validate the IMG1 header and complete directory.
 * Return 0 if valid, or -1 if invalid.
 */
int image_validate(void);

/* Return the program count, or -1 if the image is invalid. */
int image_count(void);

/* Copy the indexed program name into name.
 * Return 0 on success, or -1 on error.
 */
int image_name(unsigned index, char *name, unsigned capacity);

/* Find a program by name.
 * On success, set elf_data and elf_size and return 0.
 * Return -1 if the image or requested program is invalid.
 */
int image_find(const char *name,
               const uint8_t **elf_data,
               uint32_t *elf_size);

#endif
