#include "../../library.h"

/* Line numbers in futag-contexts.json refer to this file. */
void consumer(const char *data, size_t size) {
    obj_t *o = obj_create();
    obj_modify(o, 300);
    obj_tune(o, 2.5, ',', 0x80000000u, "a\"b\n");
    obj_target(o, data, size);
}
