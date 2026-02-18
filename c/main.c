/*
 * MeowHash v6 — CLI Tool
 *
 * Usage:
 *   ./meowhash "string"
 *   ./meowhash --file <path>
 *   ./meowhash              (hashes empty string)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "meow_hash_v6.h"

static void print_usage(const char *prog) {
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  %s \"string\"         Hash a string\n", prog);
    fprintf(stderr, "  %s --file <path>    Hash a file\n", prog);
    fprintf(stderr, "  %s                  Hash empty string\n", prog);
}

int main(int argc, char *argv[]) {
    char hex[65];

    if (argc == 1) {
        /* Hash empty string */
        meow_hash_v6_hex(NULL, 0, hex);
        printf("%s\n", hex);
        return 0;
    }

    if (argc == 2 && strcmp(argv[1], "--help") == 0) {
        print_usage(argv[0]);
        return 0;
    }

    if (argc == 3 && strcmp(argv[1], "--file") == 0) {
        /* Hash file contents */
        FILE *f = fopen(argv[2], "rb");
        if (!f) {
            fprintf(stderr, "Error: cannot open file '%s'\n", argv[2]);
            return 1;
        }
        fseek(f, 0, SEEK_END);
        long fsize = ftell(f);
        fseek(f, 0, SEEK_SET);

        uint8_t *data = NULL;
        if (fsize > 0) {
            data = (uint8_t *)malloc(fsize);
            if (!data) {
                fprintf(stderr, "Error: out of memory\n");
                fclose(f);
                return 1;
            }
            if (fread(data, 1, fsize, f) != (size_t)fsize) {
                fprintf(stderr, "Error: failed to read file\n");
                free(data);
                fclose(f);
                return 1;
            }
        }
        fclose(f);

        meow_hash_v6_hex(data, (size_t)fsize, hex);
        printf("%s  %s\n", hex, argv[2]);
        free(data);
        return 0;
    }

    if (argc == 2) {
        /* Hash string argument */
        const char *s = argv[1];
        meow_hash_v6_hex((const uint8_t *)s, strlen(s), hex);
        printf("%s\n", hex);
        return 0;
    }

    print_usage(argv[0]);
    return 1;
}
