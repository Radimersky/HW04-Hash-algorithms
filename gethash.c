#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include "hash_helper.h"
#include <inttypes.h>

unsigned short hashXor(unsigned char *content, long length);
unsigned short hashC16(unsigned char *content, long length);
void hashMD5(unsigned char *content, unsigned long length, unsigned char *result);
char *readFromStdIn();
uint32_t rc_crc32(uint32_t crc, const char *buf, size_t len);

unsigned long contentLength = 0; // Length of file
char *pcontentPath;              // Path to file
unsigned char *content;          // Array of file content

int main(int argc, char **argv)
{
    // Arguments
    bool md5 = false;
    bool c16 = false;
    bool c32 = false;
    bool xor = false;
    bool hex = false;
    bool file = false;

    if (argc < 2) // Check if some arguments were passed
    {
        fprintf(stderr, "%s", "no arguments were passed\n");
        exit(-1);
    }

    // Check which arguments were passed
    for (int i = 1; i < argc; ++i) {
        if (strcmp("-md5", argv[i]) == 0) {
            md5 = true;
        } else if (strcmp("-c16", argv[i]) == 0) {
            c16 = true;
        } else if (strcmp("-c32", argv[i]) == 0) {
            c32 = true;
        } else if (strcmp("-xor", argv[i]) == 0) {
            xor = true;
        } else if (strcmp("-hex", argv[i]) == 0) {
            hex = true;
        } else if (strcmp("-f", argv[i]) == 0) {
            pcontentPath = argv[i + 1];
            file = true;
            i++; // Skip file path parameter
        } else {
            fprintf(stderr, "%s", "Invalid input parameter\n");
            exit(-1);
        }
    }

    if (md5 == false && c16 == false && c32 == false && xor == false) { // Check if there were some hash arguments
        fprintf(stderr, "%s", "No hash argument was given\n");
        exit(-1);
    }

    // Store file content in an array
    if (file) {
        FILE *fileptr;

        fileptr = fopen(pcontentPath, "rb"); // Open the file in binary mode
        if (fileptr == NULL) {
            fprintf(stderr, "%s", "Failed to open file\n");
            exit(-1);
        }
        fseek(fileptr, 0, SEEK_END);                   // Jump to the end of the file
        contentLength = (unsigned long)ftell(fileptr); // Get the current byte offset in the file
        rewind(fileptr);                               // Jump back to the beginning of the file

        content = (unsigned char *)calloc((contentLength + 1), 8); // Enough memory for file + \0

        while (!content) {                                             // If allocation fails, try again
            content = (unsigned char *)calloc((contentLength + 1), 8); // Enough memory for file + \0
        }

        fread(content, contentLength, 1, fileptr); // Read in the entire file
        if ((fclose(fileptr)) != 0) {              // Close the file
            fprintf(stderr, "%s", "Failed to close file\n");
            exit(-1);
        }
    } else {
        content = (unsigned char *)readFromStdIn();
        if (content == NULL) {
            content = (unsigned char *)"\0";
        }
    }

    printf("Length: %ld bytes\n", contentLength); // Print length of binary

    if (xor) {
        unsigned short xoredHash = hashXor(content, contentLength); // Get xored hash
        if (hex) {
            printf("XOR: 0x%02x\n", xoredHash);
        } else {
            printf("XOR: %d\n", xoredHash);
        }
    }

    if (c16) {
        unsigned short c16Hash = hashC16(content, contentLength); // Get crc-16 hash
        if (hex) {
            printf("CRC-16: 0x%04x\n", c16Hash);
        } else {
            printf("CRC-16: %d\n", c16Hash);
        }
    }

    if (c32) {
        unsigned int c32Hash = rc_crc32(0, (const char *)content, contentLength);

        if (hex) {
            printf("CRC-32: 0x%08x\n", c32Hash);
        } else {
            printf("CRC-32: %u\n", c32Hash);
        }
    }

    if (md5) {
        unsigned char md5Hash[16];
        hashMD5(content, contentLength, md5Hash); // Get MD5 hash

        printf("%s", "MD5: "); // Print result
        for (int i = 0; i < 16; ++i) {
            printf("%02x", md5Hash[i]);
        }
        putchar('\n');
        free(content); // Free content
    }
}

/**
 * XOR hashes content
 * @param content to be xored
 * @param length of content in bytes
 * @return hash
 */
unsigned short hashXor(unsigned char *content, long length)
{
    unsigned short result = content[0];

    for (long i = 1; i < length; ++i) {
        result ^= content[i];
    }

    return result;
}

/**
 * Hashes content with CRC-16
 * @param content to hash
 * @param length of content in bytes
 * @return
 */
unsigned short hashC16(unsigned char *content, long length)
{
    crc16_context c16; // Create structure
    crc16_init(&c16);  // Init structure

    for (int i = 0; i < length; ++i) {
        crc16_update(&c16, content[i]);
    }
    return c16.crc;
}

/**
 * Hashes content with MD5
 * @param content to hash
 * @param length of content
 * @param result where hash should be stored
 */
void hashMD5(unsigned char *content, unsigned long length, unsigned char *result)
{
    MD5_CTX md5;    // Create structure
    MD5_Init(&md5); // Init structure
    MD5_Update(&md5, content, length);
    MD5_Final(result, &md5);
}

/**
 * Reads input from stdin
 * @return buffered input
 */
char *readFromStdIn()
{
    char *buffer = NULL;
    size_t alloc_size = 1;
    size_t size = 0;
    int ch = 0;

    while ((ch = getchar()) != EOF) {
        if ((size + 1) >= alloc_size) {
            alloc_size *= 2;
            char *pOld = buffer;
            buffer = (char *)realloc(buffer, (alloc_size + 1) * sizeof(char));
            if (!buffer) {
                free(pOld);
                return NULL;
            }
        }
        contentLength++;
        buffer[size++] = (char)ch;
    }

    if (!buffer) {
        printf("%d/n", 6);
        return NULL; // First character was new line or EOF
    }

    buffer[size] = '\0';
    return buffer;
}

/**
 * Calculates CRC32 Hash
 * @param crc init hash
 * @param buf content to hash
 * @param len length of content
 * @return CRC32 hash
 */
uint32_t rc_crc32(uint32_t crc, const char *buf, size_t len)
{
    static uint32_t table[256];
    static int have_table = 0;
    uint32_t rem;
    uint8_t octet;
    int i, j;
    const char *p, *q;

    /* This check is not thread safe; there is no mutex. */
    if (have_table == 0) {
        /* Calculate CRC table. */
        for (i = 0; i < 256; i++) {
            rem = i; /* remainder from polynomial division */
            for (j = 0; j < 8; j++) {
                if (rem & 1) {
                    rem >>= 1;
                    rem ^= 0xedb88320;
                } else
                    rem >>= 1;
            }
            table[i] = rem;
        }
        have_table = 1;
    }

    crc = ~crc;
    q = buf + len;
    for (p = buf; p < q; p++) {
        octet = *p; /* Cast to unsigned octet. */
        crc = (crc >> 8) ^ table[(crc & 0xff) ^ octet];
    }
    return ~crc;
}