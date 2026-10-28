#include "image.h"
#include <stddef.h>
static int bytes_equal(const uint8_t *a, const char *b, unsigned n)
{
    for (unsigned i = 0; i < n; i++)
        if (a[i] != (uint8_t)b[i])
            return 0;
    return 1;
}

static void bytes_copy(void *dest, const void *src, unsigned n)
{
    uint8_t *d = dest;
    const uint8_t *s = src;

    for (unsigned i = 0; i < n; i++)
        d[i] = s[i];
}

static int strings_equal(const char *a, const char *b)
{
    while (*a && *a == *b) {
        a++;
        b++;
    }
    return *a == *b;
}

#define IMAGE_BASE       0x00200000u
#define IMAGE_MAX_SIZE   0x00200000u
#define IMAGE_MAX_COUNT  32u
#define IMAGE_HEADER_SIZE 20u
#define IMAGE_ENTRY_SIZE  24u

#define IMAGE_VERSION 1u

static int valid_name_char(uint8_t c)
{
    return (c >= 'A' && c <= 'Z') ||
           (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') ||
           c == '_' || c == '-';
}

typedef struct {
    char magic[4];
    uint32_t version;
    uint32_t image_size;
    uint32_t program_count;
    uint32_t directory_offset;
} image_header_t;

typedef struct {
    char name[16];
    uint32_t offset;
    uint32_t size;
} image_entry_t;

static const uint8_t *image_data(void)
{
    return (const uint8_t *)IMAGE_BASE;
}

static uint32_t read_u32(const uint8_t *p)
{
    return (uint32_t)p[0]
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

static int range_valid(uint32_t offset, uint32_t size,
                       uint32_t total_size)
{
    return offset <= total_size &&
           size <= total_size - offset;
}

int image_validate(void)
{
    const uint8_t *data = image_data();

    if (!bytes_equal(data, "IMG1", 4))
        return -1;

    uint32_t version = read_u32(data + 4);
    uint32_t image_size = read_u32(data + 8);
    uint32_t count = read_u32(data + 12);
    uint32_t directory_offset = read_u32(data + 16);

    if (version != IMAGE_VERSION ||
        image_size < IMAGE_HEADER_SIZE ||
        image_size > IMAGE_MAX_SIZE ||
        count == 0 || count > IMAGE_MAX_COUNT)
        return -1;

    if (directory_offset < IMAGE_HEADER_SIZE ||
        (directory_offset & 3u) != 0 ||
        !range_valid(directory_offset, count * IMAGE_ENTRY_SIZE,
                     image_size))
        return -1;

    uint32_t directory_end =
        directory_offset + count * IMAGE_ENTRY_SIZE;

    for (uint32_t i = 0; i < count; i++) {
        const uint8_t *entry =
            data + directory_offset + i * IMAGE_ENTRY_SIZE;

        uint32_t offset = read_u32(entry + 16);
        uint32_t size = read_u32(entry + 20);

        if (entry[0] == '\0' || size == 0)
            return -1;

        int terminated = 0;
        for (unsigned j = 0; j < 16; j++) {
            if (entry[j] == '\0') {
                terminated = 1;
                break;
            }
            if (!valid_name_char(entry[j]))
                return -1;
        }

        if (!terminated)
            return -1;

        if ((offset & 3u) != 0 ||
            !range_valid(offset, size, image_size) ||
            offset < directory_end)
            return -1;

        for (uint32_t k = 0; k < i; k++) {
            const uint8_t *previous =
                data + directory_offset + k * IMAGE_ENTRY_SIZE;

            unsigned j = 0;
            while (j < 16 && previous[j] != '\0' &&
                   previous[j] == entry[j])
                j++;

            if (j < 16 && previous[j] == entry[j])
                return -1;

            uint32_t previous_offset = read_u32(previous + 16);
            uint32_t previous_size = read_u32(previous + 20);

            if (offset < previous_offset + previous_size &&
                previous_offset < offset + size)
                return -1;
        }
    }

    return 0;
}

static int get_entry(unsigned index, image_entry_t *entry)
{
    const uint8_t *data = image_data();

    if (image_validate() != 0)
        return -1;

    uint32_t count = read_u32(data + 12);
    uint32_t directory_offset = read_u32(data + 16);

    if (index >= count)
        return -1;

    const uint8_t *p = data + directory_offset
                     + index * IMAGE_ENTRY_SIZE;

    bytes_copy(entry->name, p, 16);
    entry->offset = read_u32(p + 16);
    entry->size = read_u32(p + 20);

    if (entry->name[0] == '\0' || entry->size == 0)
        return -1;

    if (!range_valid(entry->offset, entry->size,
                     read_u32(data + 8)))
        return -1;

    return 0;
}

int image_count(void)
{
    if (image_validate() != 0)
        return -1;

    return (int)read_u32(image_data() + 12);
}

int image_name(unsigned index, char *name, unsigned capacity)
{
    image_entry_t entry;

    if (name == NULL || capacity == 0)
        return -1;

    if (get_entry(index, &entry) != 0)
        return -1;

    unsigned length = 0;
    while (length < sizeof(entry.name) &&
           entry.name[length] != '\0')
        length++;

    if (length == sizeof(entry.name))
        return -1;

    if (capacity > 16)
        return -1;

    if (length + 1 > capacity) {
       unsigned copy_length = capacity - 1;
       bytes_copy(name, entry.name, copy_length);
       name[copy_length] = '\0';

       return -1;
}

bytes_copy(name, entry.name, length);
name[length] = '\0';
return 0;
}

int image_find(const char *name,
               const uint8_t **elf_data,
               uint32_t *elf_size)
{
    if (name == NULL || elf_data == NULL || elf_size == NULL)
        return -1;

    int count = image_count();
    if (count < 0)
        return -1;

    for (unsigned i = 0; i < (unsigned)count; i++) {
        image_entry_t entry;

        if (get_entry(i, &entry) != 0)
            return -1;

        if (strings_equal(name, entry.name)) {
            *elf_data = image_data() + entry.offset;
            *elf_size = entry.size;
            return 0;
        }
    }

    return -1;
}
