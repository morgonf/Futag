#include "../../library.h"

/* Line numbers in futag-contexts.json refer to this file. */
void consumer(const char *input, const char *data, size_t size) {
    obj_t *o = obj_create();
    obj_configure(o, MODE_SAFE, input);
    obj_target(o, data, size);
}
