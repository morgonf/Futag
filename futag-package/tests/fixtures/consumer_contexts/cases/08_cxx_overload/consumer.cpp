#include "../../library.h"

/* Line numbers in futag-contexts.json refer to this file. */
void consumer(const char *data, size_t size) {
    obj_t *o = obj_create();
    process(o, 1, 2);
    obj_target(o, data, size);
}
