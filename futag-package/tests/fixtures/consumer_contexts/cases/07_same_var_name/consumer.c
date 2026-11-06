#include "../../library.h"

/* Line numbers in futag-contexts.json refer to this file. */
void consumer(const char *data, size_t size) {
    {
        obj_t *h = obj_create();
        obj_modify(h, 1);
    }
    {
        obj_t *h = obj_create();
        obj_target(h, data, size);
    }
}
