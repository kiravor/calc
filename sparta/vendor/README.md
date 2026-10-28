cJSON v1.7.19, upstream commit
`c859b25da02955fef659d658b8f324b5cde87be3`:
https://github.com/DaveGamble/cJSON/tree/v1.7.19

`cJSON.c` and `cJSON.h` are unmodified. License: [MIT](cJSON.LICENSE).
The wrapper in `src/common.c` adds duplicate-key, depth, UTF-8 and embedded-NUL
validation, and serializes parsing without relying on cJSON's global error pointer.
