#include "../../library.h"

/* Line numbers in futag-contexts.json refer to this file. */
void consumer(int flag, const char *data, size_t size) {
    obj_t *o = obj_create();
    if (flag)
        obj_modify(o, 1);
    else
        obj_modify(o, 2);
    obj_target(o, data, size);
}
