#include "../../library.h"

/* Line numbers in futag-contexts.json refer to this file. */
void consumer(const char *data, size_t size) {
    obj_t *o = obj_create();
    obj_modify(o, 7);
    obj_attach(o, cfg_from(o));
    obj_target(o, data, size);
}
