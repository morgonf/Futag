#include "../../library.h"

/* Line numbers in futag-contexts.json refer to this file. */
void consumer(const char *data, size_t size) {
    obj_t *a = obj_create();
    obj_modify(a, 1);
    obj_t *b = obj_create_from(a);
    obj_modify(b, 2);
    obj_target(b, data, size);
}
